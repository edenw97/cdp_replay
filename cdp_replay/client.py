#!/usr/bin/env python3
"""Replay HTTP requests from a CDP capture file."""

from __future__ import annotations

import argparse
import http.client
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
)


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


def replay_one(record: ReplayRecord, args: argparse.Namespace) -> tuple[bool, str]:
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
        response_body = response.read()
    finally:
        connection.close()

    problems: list[str] = []
    if record.response_status is not None and response.status != record.response_status:
        problems.append(f"status expected {record.response_status}, got {response.status}")
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
            f"{response.status} ({detail})"
        )

    return True, (
        f"[client] OK [{record.index}] {record.method} {record.path_query} -> {response.status}"
    )


def main(args: argparse.Namespace) -> int:
    records, skipped = load_replay_records(args.capture, require_response_status=True)
    selected = filter_records(records, args)

    print(
        f"[client] loaded {len(records)} replayable records from {args.capture}"
        f" (skipped {skipped})"
    )
    if args.proxy is None:
        destination = args.base_url
    else:
        destination = f"{args.base_url} via proxy {args.proxy[0]}:{args.proxy[1]}"
    print(f"[client] replaying {len(selected)} requests against {destination}")

    previous: ReplayRecord | None = None
    mismatches = 0

    for position, record in enumerate(selected, start=1):
        sleep_for_record_gap(previous, record, args.pace_factor)
        previous = record

        try:
            ok, message = replay_one(record, args)
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

    print(f"[client] finished with {mismatches} mismatch/error(s)")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main(parse_args()))
