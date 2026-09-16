#!/usr/bin/env python3
"""Self-contained replay: start the server, run the client, report pass/fail."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
import threading

from . import client
from . import server
from .common import load_replay_records


DESCRIPTION = (
    "Start the replay server, replay every recorded request against it via the "
    "client, and report pass/fail. Without --proxy the client connects to the "
    "server directly; with --proxy all traffic is routed through the given HTTP "
    "proxy, replaying the capture through the device under test."
)


def is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_loopback:
                return False
        except ValueError:
            return False
    return True


def local_address_towards(host: str) -> str | None:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except OSError:
        return None
    for family, _, _, _, sockaddr in infos:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect(sockaddr)
                return sock.getsockname()[0]
        except OSError:
            continue
    return None


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--host",
        default=None,
        help=(
            "address the replay server binds to "
            "(default: 127.0.0.1, or 0.0.0.0 when --proxy points at a remote host)"
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="replay server port (default 8080, 0 picks a free port)",
    )
    parser.add_argument(
        "--tls-cert",
        default=None,
        help="path to the TLS certificate PEM for the embedded server (enables HTTPS with ALPN h2/http1.1)",
    )
    parser.add_argument(
        "--tls-key",
        default=None,
        help="path to the TLS private key PEM for the embedded server",
    )
    client.add_arguments(parser, base_url_default=None, verify_body_default=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cdp-replay replay",
        description=DESCRIPTION,
    )
    add_arguments(parser)
    return parser.parse_args(argv)


def main(args: argparse.Namespace) -> int:
    records, skipped = load_replay_records(args.capture, require_response_status=True)
    print(
        f"[replay] loaded {len(records)} replayable records from {args.capture}"
        f" (skipped {skipped})"
    )

    proxy_is_remote = args.proxy is not None and not is_loopback_host(args.proxy[0])
    host = args.host
    if host is None:
        host = "0.0.0.0" if proxy_is_remote else "127.0.0.1"
        if proxy_is_remote:
            print("[replay] proxy is remote; binding the replay server to 0.0.0.0")

    try:
        tls_context = server.build_tls_context(args.tls_cert, args.tls_key)
    except (ValueError, OSError, ssl.SSLError) as exc:
        print(f"[replay] {exc}")
        return 2

    try:
        replay_server = server.ReplayServer(
            (host, args.port),
            server.ReplayRequestHandler,
            matcher=server.ReplayMatcher(records),
            verbose=False,
            tls_context=tls_context,
        )
    except OSError as exc:
        print(f"[replay] could not start the replay server on {host}:{args.port}: {exc}")
        return 1

    address = replay_server.server_address
    bound_host = str(address[0])
    bound_port = int(address[1])
    wildcard = bound_host in ("", "0.0.0.0", "::")
    scheme = "https" if tls_context is not None else "http"
    base_url = args.base_url
    if base_url is None:
        if wildcard:
            base_host = "127.0.0.1"
            if args.proxy is not None:
                routed = local_address_towards(args.proxy[0])
                if routed:
                    base_host = routed
                elif proxy_is_remote:
                    print(
                        "[replay] warning: could not determine a routable local address "
                        f"towards the proxy {args.proxy[0]}; the base URL falls back to "
                        f"{base_host}, which a remote proxy cannot reach. Pass --base-url "
                        "with an address the proxy can route to."
                    )
        else:
            base_host = bound_host
            if args.proxy is not None and proxy_is_remote and is_loopback_host(bound_host):
                print(
                    "[replay] warning: the server is listening on loopback but the proxy "
                    f"({args.proxy[0]}) is remote, so the proxy cannot reach it. "
                    "Drop --host to bind 0.0.0.0 automatically, or pass a routable --host."
                )
        base_url = f"{scheme}://{base_host}:{bound_port}"

    print(f"[replay] server listening on {scheme}://{bound_host}:{bound_port}")
    print(f"[replay] target base URL: {base_url}")
    threading.Thread(target=replay_server.serve_forever, daemon=True).start()

    client_args = argparse.Namespace(**vars(args))
    client_args.base_url = base_url
    if tls_context is not None and not client_args.insecure:
        client_args.insecure = True
        print("[replay] note: client certificate verification disabled for the embedded TLS server")
    try:
        rc = client.main(client_args)
    finally:
        replay_server.shutdown()
        replay_server.server_close()

    if rc == 0:
        print("[replay] PASS")
    else:
        print("[replay] FAIL")
    return rc


if __name__ == "__main__":
    raise SystemExit(main(parse_args()))
