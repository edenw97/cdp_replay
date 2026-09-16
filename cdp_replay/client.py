#!/usr/bin/env python3
"""Replay HTTP requests from a CDP capture file."""

from __future__ import annotations

import argparse
import http.client
import socket
import ssl
import time
import urllib.parse
from typing import Iterable

from .common import (
    ReplayRecord,
    header_lookup,
    load_replay_records,
    rewrite_url_to_base,
    sanitize_request_headers,
    sha256_hex,
    split_header_value,
)

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.exceptions

    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


DESCRIPTION = (
    "Replay HTTP requests from a capture JSONL file. Use --base-url to point "
    "the replay at a local mock server. For HTTPS endpoints with a self-signed "
    "certificate, combine an https:// --base-url with --insecure (this replaces "
    "the former cdp_replay_client_tls.py)."
)


def add_arguments(
    parser: argparse.ArgumentParser,
    *,
    base_url_default: str | None = "http://127.0.0.1:8080",
    verify_body_default: bool = False,
) -> None:
    if base_url_default is None:
        base_url_help = (
            "rewrite each recorded request to this base URL while keeping path/query "
            "(default: the replay server address)"
        )
    else:
        base_url_help = (
            "rewrite each recorded request to this base URL while keeping path/query "
            f"(default: {base_url_default})"
        )
    parser.add_argument("capture", help="path to the capture JSONL file")
    parser.add_argument(
        "--base-url",
        default=base_url_default,
        help=base_url_help,
    )
    parser.add_argument(
        "--proxy",
        type=parse_proxy,
        default=None,
        metavar="HOST:PORT",
        help="route all requests through an explicit HTTP proxy (CONNECT for https targets)",
    )
    parser.add_argument(
        "--host-filter",
        default=None,
        help="comma-separated list of original hosts to replay",
    )
    parser.add_argument(
        "--url-filter",
        default=None,
        help="comma-separated list of original captured URLs to replay",
    )
    parser.add_argument(
        "--method-filter",
        default=None,
        help="comma-separated list of HTTP methods to replay",
    )
    parser.add_argument(
        "--resource-type-filter",
        default=None,
        help="comma-separated list of recorded resource types to replay",
    )
    parser.add_argument("--limit", type=int, default=None, help="max requests to replay")
    parser.add_argument(
        "--pace-factor",
        type=float,
        default=0.0,
        help=(
            "multiply recorded inter-request delays by this factor "
            "(0 means no delay, 1 means original spacing)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="per-request timeout in seconds",
    )
    parser.add_argument(
        "--verify-body",
        action=argparse.BooleanOptionalAction,
        default=verify_body_default,
        help="compare response body SHA256 with the recorded response body",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="stop immediately on the first transport or verification failure",
    )
    parser.add_argument(
        "--preserve-host",
        action="store_true",
        help="send the original Host header instead of the rewritten base host",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification for HTTPS targets",
    )
    parser.add_argument(
        "--http2",
        action="store_true",
        help=(
            "force HTTP/2 for every request (alias for --protocol h2; "
            "requires an https target, default replays each request with its "
            "recorded protocol)"
        ),
    )
    parser.add_argument(
        "--protocol",
        choices=["auto", "h1", "h2"],
        default="auto",
        help=(
            "HTTP version to use for replay: auto replays each request with its "
            "recorded protocol over https targets (HTTP/3 falls back to HTTP/2, "
            "plain http targets always use HTTP/1.1), h1/h2 force one version "
            "(h2 requires https) (default: auto)"
        ),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cdp-replay client",
        description=DESCRIPTION,
    )
    add_arguments(parser)
    return parser.parse_args(argv)


def parse_proxy(value: str) -> tuple[str, int]:
    host, sep, port_text = value.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not sep or not host or not port_text.isdigit():
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {value!r}")
    port = int(port_text)
    if not 0 < port < 65536:
        raise argparse.ArgumentTypeError(f"proxy port out of range: {value!r}")
    return host, port


def split_filter(value: str | None) -> set[str] | None:
    if value is None:
        return None
    items = {item.strip() for item in value.split(",") if item.strip()}
    return items or None


def filter_records(records: Iterable[ReplayRecord], args: argparse.Namespace) -> list[ReplayRecord]:
    host_filter = split_filter(args.host_filter)
    url_filter = split_filter(args.url_filter)
    method_filter = split_filter(args.method_filter)
    resource_filter = split_filter(args.resource_type_filter)
    filtered: list[ReplayRecord] = []

    for record in records:
        if host_filter and record.host not in host_filter:
            continue
        if url_filter and record.url not in url_filter:
            continue
        if method_filter and record.method not in method_filter:
            continue
        if resource_filter and (record.resource_type or "") not in resource_filter:
            continue
        filtered.append(record)
        if args.limit is not None and len(filtered) >= args.limit:
            break

    return filtered


def sleep_for_record_gap(previous: ReplayRecord | None, current: ReplayRecord, pace_factor: float) -> None:
    if pace_factor <= 0 or previous is None:
        return
    if previous.recorded_wall_time is None or current.recorded_wall_time is None:
        return
    delay = max(0.0, current.recorded_wall_time - previous.recorded_wall_time) * pace_factor
    if delay > 0:
        time.sleep(delay)


def open_connection(
    target_url: str,
    *,
    timeout: float,
    insecure: bool,
    proxy: tuple[str, int] | None = None,
) -> tuple[http.client.HTTPConnection, str, str | None]:
    parsed = urllib.parse.urlsplit(target_url)
    path_query = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    port = parsed.port
    if parsed.hostname is None:
        raise ValueError(f"Base URL is missing a hostname: {target_url!r}")

    if parsed.scheme == "https":
        context = None
        if insecure:
            context = ssl._create_unverified_context()
        if proxy is None:
            connection = http.client.HTTPSConnection(
                parsed.hostname,
                port or 443,
                timeout=timeout,
                context=context,
            )
        else:
            connection = http.client.HTTPSConnection(
                proxy[0],
                proxy[1],
                timeout=timeout,
                context=context,
            )
            connection.set_tunnel(parsed.hostname, port or 443)
        return connection, path_query, parsed.netloc if proxy is not None else None

    if parsed.scheme == "http":
        if proxy is None:
            return (
                http.client.HTTPConnection(parsed.hostname, port or 80, timeout=timeout),
                path_query,
                None,
            )
        connection = http.client.HTTPConnection(proxy[0], proxy[1], timeout=timeout)
        return connection, target_url, parsed.netloc

    raise ValueError(f"Unsupported URL scheme in {target_url!r}")


class H2TransportError(Exception):
    """Raised when the HTTP/2 transport fails."""


class _H2Response:
    def __init__(self) -> None:
        self.status: int | None = None
        self.headers: list[tuple[str, str]] = []
        self.body = bytearray()


def _h2_status_code(headers: list[tuple[str, str]]) -> int | None:
    for name, value in headers:
        if name == ":status":
            try:
                return int(value)
            except ValueError:
                return None
    return None


class _H2ClientConnection:
    def __init__(self, sock: socket.socket, timeout: float) -> None:
        sock.settimeout(timeout)
        self._sock = sock
        self._conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        )
        self._conn.initiate_connection()
        self._send_pending()

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def _send_pending(self) -> None:
        data = self._conn.data_to_send()
        if data:
            self._sock.sendall(data)

    def _receive_events(self) -> list:
        data = self._sock.recv(65536)
        if not data:
            raise H2TransportError("connection closed by peer")
        try:
            return self._conn.receive_data(data)
        except h2.exceptions.H2Error as exc:
            raise H2TransportError(f"HTTP/2 protocol error: {exc}") from exc

    def request(
        self,
        *,
        method: str,
        scheme: str,
        authority: str,
        path_query: str,
        header_items: list[tuple[str, str]],
        body: bytes,
    ) -> _H2Response:
        stream_id = self._conn.get_next_available_stream_id()
        pseudo_headers = [
            (":method", method),
            (":scheme", scheme),
            (":authority", authority),
            (":path", path_query or "/"),
        ]
        payload = memoryview(body)
        try:
            self._conn.send_headers(
                stream_id,
                pseudo_headers + header_items,
                end_stream=not body,
            )
            self._send_pending()
            response = _H2Response()
            offset = 0
            while True:
                while offset < len(payload):
                    window = self._conn.local_flow_control_window(stream_id)
                    chunk = min(
                        window,
                        self._conn.max_outbound_frame_size,
                        len(payload) - offset,
                    )
                    if chunk <= 0:
                        break
                    end_stream = offset + chunk == len(payload)
                    self._conn.send_data(
                        stream_id,
                        payload[offset : offset + chunk],
                        end_stream=end_stream,
                    )
                    offset += chunk
                self._send_pending()
                for event in self._receive_events():
                    if isinstance(event, h2.events.ResponseReceived):
                        response.headers = list(event.headers)
                    elif isinstance(event, h2.events.DataReceived):
                        response.body += event.data
                        self._conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, (h2.events.StreamEnded, h2.events.TrailersReceived)):
                        self._send_pending()
                        return response
                    elif isinstance(event, h2.events.StreamReset):
                        raise H2TransportError(
                            f"stream {event.stream_id} reset by peer: {event.error_code}"
                        )
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        raise H2TransportError("connection terminated by peer (GOAWAY)")
                    elif isinstance(event, h2.events.PingReceived):
                        self._conn.ping_ack(event.ping_data)
                self._send_pending()
        except h2.exceptions.H2Error as exc:
            raise H2TransportError(f"HTTP/2 protocol error: {exc}") from exc
        except OSError as exc:
            raise H2TransportError(f"HTTP/2 connection failed: {exc}") from exc


class H2Transport:
    """Pooled HTTP/2 connections, one per (scheme, host, port)."""

    def __init__(
        self,
        *,
        timeout: float,
        insecure: bool,
        proxy: tuple[str, int] | None = None,
    ) -> None:
        self._timeout = timeout
        self._insecure = insecure
        self._proxy = proxy
        self._connections: dict[tuple[str, str, int], _H2ClientConnection] = {}

    def close(self) -> None:
        for connection in self._connections.values():
            connection.close()
        self._connections.clear()

    def request(
        self,
        *,
        method: str,
        scheme: str,
        host: str,
        port: int,
        authority: str,
        path_query: str,
        header_items: list[tuple[str, str]],
        body: bytes,
    ) -> _H2Response:
        key = (scheme, host, port)
        connection = self._connections.get(key)
        if connection is None:
            connection = self._open(scheme, host, port)
            self._connections[key] = connection
        try:
            return connection.request(
                method=method,
                scheme=scheme,
                authority=authority,
                path_query=path_query,
                header_items=header_items,
                body=body,
            )
        except Exception:
            connection.close()
            if self._connections.get(key) is connection:
                del self._connections[key]
            raise

    def _open(self, scheme: str, host: str, port: int) -> _H2ClientConnection:
        if scheme != "https":
            raise H2TransportError("HTTP/2 is only spoken over TLS (https) targets")
        if self._proxy is None:
            sock = socket.create_connection((host, port), timeout=self._timeout)
        else:
            sock = socket.create_connection(self._proxy, timeout=self._timeout)
            try:
                self._connect_via_proxy(sock, host, port)
            except Exception:
                sock.close()
                raise
        try:
            sock = self._wrap_tls(sock, host)
        except Exception:
            sock.close()
            raise
        return _H2ClientConnection(sock, self._timeout)

    def _wrap_tls(self, sock: socket.socket, server_name: str) -> socket.socket:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_alpn_protocols(["h2"])
        if self._insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            wrapped = context.wrap_socket(sock, server_hostname=server_name)
        except (OSError, ssl.SSLError) as exc:
            raise H2TransportError(f"TLS handshake with {server_name} failed: {exc}") from exc
        negotiated = wrapped.selected_alpn_protocol()
        if negotiated != "h2":
            wrapped.close()
            raise H2TransportError(
                f"target did not negotiate HTTP/2 over ALPN (got {negotiated!r}); "
                "remove --http2 or enable h2 on the target"
            )
        return wrapped

    def _connect_via_proxy(self, sock: socket.socket, host: str, port: int) -> None:
        target = f"{host}:{port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                raise H2TransportError("proxy closed connection during CONNECT")
            buffer += chunk
            if len(buffer) > 65536:
                raise H2TransportError("oversized CONNECT response from proxy")
        head, _, trailing = buffer.partition(b"\r\n\r\n")
        if trailing:
            raise H2TransportError("unexpected data after the proxy CONNECT response")
        status_line = head.split(b"\r\n", 1)[0]
        parts = status_line.split(None, 2)
        if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) != 200:
            detail = status_line.decode("latin-1", "replace")
            raise H2TransportError(f"proxy CONNECT failed: {detail}")


def select_http_version(record: ReplayRecord, args: argparse.Namespace, scheme: str) -> str:
    if scheme != "https":
        return "h1"
    if args.http2 or args.protocol == "h2":
        return "h2"
    if args.protocol == "h1":
        return "h1"
    if record.http_version in ("h2", "h3"):
        return "h2"
    return "h1"


def replay_one(
    record: ReplayRecord,
    args: argparse.Namespace,
    transport: H2Transport | None = None,
) -> tuple[bool, str]:
    target_url = rewrite_url_to_base(record.url, args.base_url) if args.base_url else record.url
    headers = sanitize_request_headers(
        record.request_headers,
        preserve_host=args.preserve_host,
        original_host=record.host,
    )
    headers["X-Replay-Original-URL"] = record.url
    headers["X-Replay-Record-Index"] = str(record.index)
    if record.request_id:
        headers["X-Replay-Request-Id"] = record.request_id

    target_scheme = urllib.parse.urlsplit(target_url).scheme
    use_h2 = select_http_version(record, args, target_scheme) == "h2" and transport is not None
    if use_h2:
        parsed = urllib.parse.urlsplit(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Unsupported target URL: {target_url!r}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        authority = parsed.netloc
        if args.preserve_host:
            authority = record.host
        header_items = [
            (name.lower(), piece)
            for name, value in headers.items()
            if name.lower() != "host"
            for piece in split_header_value(value)
        ]
        h2_response = transport.request(
            method=record.method,
            scheme=parsed.scheme,
            host=parsed.hostname,
            port=port,
            authority=authority,
            path_query=record.path_query,
            header_items=header_items,
            body=record.request_body,
        )
        status = _h2_status_code(h2_response.headers)
        if status is None:
            raise H2TransportError("response did not include a :status pseudo-header")
        response_body = bytes(h2_response.body)
    else:
        connection, request_target, origin_authority = open_connection(
            target_url,
            timeout=args.timeout,
            insecure=args.insecure,
            proxy=args.proxy,
        )
        if origin_authority is not None and header_lookup(headers, "Host") is None:
            headers["Host"] = origin_authority
        try:
            connection.request(
                record.method,
                request_target,
                body=record.request_body or None,
                headers=headers,
            )
            response = connection.getresponse()
            status = response.status
            response_body = response.read()
        finally:
            connection.close()

    problems: list[str] = []
    if record.response_status is not None and status != record.response_status:
        problems.append(f"status expected {record.response_status}, got {status}")
    if args.verify_body:
        body_hash = sha256_hex(response_body)
        if body_hash != record.response_body_hash:
            problems.append(
                f"body sha256 expected {record.response_body_hash[:12]}, got {body_hash[:12]}"
            )

    if problems:
        detail = "; ".join(problems)
        return False, (
            f"[client] MISMATCH [{record.index}] {record.method} {record.path_query} -> "
            f"{status} ({detail})"
        )

    return True, (
        f"[client] OK [{record.index}] {record.method} {record.path_query} -> {status}"
    )


def main(args: argparse.Namespace) -> int:
    records, skipped = load_replay_records(args.capture, require_response_status=True)
    selected = filter_records(records, args)

    def target_scheme(record: ReplayRecord) -> str:
        if args.base_url:
            return urllib.parse.urlsplit(args.base_url).scheme
        return urllib.parse.urlsplit(record.url).scheme

    forced_h2 = args.http2 or args.protocol == "h2"
    selections = [
        (record, select_http_version(record, args, target_scheme(record)))
        for record in selected
    ]
    if forced_h2 and any(version != "h2" for _, version in selections):
        print(
            "[client] error: --protocol h2 / --http2 requires an https target; "
            "HTTP/2 is only spoken over TLS (use --protocol h1 or an https base URL)"
        )
        return 2
    if any(version == "h2" for _, version in selections) and not H2_AVAILABLE:
        print("[client] HTTP/2 replay requires the 'h2' package (pip install h2)")
        return 2

    print(
        f"[client] loaded {len(records)} replayable records from {args.capture}"
        f" (skipped {skipped})"
    )
    if args.proxy is None:
        destination = args.base_url
    else:
        destination = f"{args.base_url} via proxy {args.proxy[0]}:{args.proxy[1]}"
    versions = [version for _, version in selections]
    h2_count = versions.count("h2")
    h1_count = versions.count("h1")
    print(
        f"[client] replaying {len(selected)} requests against {destination} "
        f"({h1_count} HTTP/1.1, {h2_count} HTTP/2)"
    )
    downgraded = sum(
        1
        for record, version in selections
        if version == "h1" and record.http_version in ("h2", "h3")
    )
    if downgraded:
        print(
            f"[client] note: {downgraded} record(s) were captured over HTTP/2 or "
            "HTTP/3 but replay over HTTP/1.1 because the target is plain http"
        )
    if not forced_h2:
        h3_count = sum(
            1
            for record, version in selections
            if version == "h2" and record.http_version == "h3"
        )
        if h3_count:
            print(
                f"[client] note: {h3_count} record(s) were captured over HTTP/3; "
                "replaying them over HTTP/2"
            )

    transport = H2Transport(timeout=args.timeout, insecure=args.insecure, proxy=args.proxy)

    previous: ReplayRecord | None = None
    mismatches = 0

    try:
        for position, record in enumerate(selected, start=1):
            sleep_for_record_gap(previous, record, args.pace_factor)
            previous = record

            try:
                ok, message = replay_one(record, args, transport)
            except Exception as exc:
                ok = False
                message = (
                    f"[client] ERROR [{record.index}] {record.method} {record.path_query} -> {exc}"
                )

            print(f"{position}/{len(selected)} {message}")
            if not ok:
                mismatches += 1
                if args.stop_on_error:
                    break
    finally:
        if transport is not None:
            transport.close()

    print(f"[client] finished with {mismatches} mismatch/error(s)")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main(parse_args()))
