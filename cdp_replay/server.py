#!/usr/bin/env python3
"""Replay recorded HTTP responses from a CDP capture file."""

from __future__ import annotations

import argparse
import json
import threading
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .common import (
    ReplayRecord,
    load_replay_records,
    sanitize_response_headers,
    sha256_hex,
)


DESCRIPTION = (
    "Serve recorded HTTP responses from a capture JSONL file. "
    "Incoming requests are matched by method + original URL/path + request body."
)


class ReplayMatcher:
    """Match incoming requests to recorded capture entries."""

    def __init__(self, records: list[ReplayRecord]) -> None:
        self._records_by_index = {record.index: record for record in records}
        self._consumed: set[int] = set()
        self._lock = threading.Lock()
        self._full_with_body: dict[tuple[str, str, str], deque[int]] = defaultdict(deque)
        self._full_any_body: dict[tuple[str, str], deque[int]] = defaultdict(deque)
        self._path_with_body: dict[tuple[str, str, str], deque[int]] = defaultdict(deque)
        self._path_any_body: dict[tuple[str, str], deque[int]] = defaultdict(deque)

        for record in records:
            self._full_with_body[(record.method, record.url, record.request_body_hash)].append(
                record.index
            )
            self._full_any_body[(record.method, record.url)].append(record.index)
            self._path_with_body[
                (record.method, record.path_query, record.request_body_hash)
            ].append(record.index)
            self._path_any_body[(record.method, record.path_query)].append(record.index)

    def match(
        self,
        *,
        method: str,
        path_query: str,
        original_url: str | None,
        body: bytes,
    ) -> tuple[ReplayRecord | None, str | None]:
        body_hash = sha256_hex(body)
        candidates: list[tuple[str, deque[int] | None]] = []

        if original_url:
            candidates.extend(
                [
                    ("url+body", self._full_with_body.get((method, original_url, body_hash))),
                    ("url", self._full_any_body.get((method, original_url))),
                ]
            )

        candidates.extend(
            [
                ("path+body", self._path_with_body.get((method, path_query, body_hash))),
                ("path", self._path_any_body.get((method, path_query))),
            ]
        )

        with self._lock:
            for match_name, queue in candidates:
                record = self._pop_next(queue)
                if record is not None:
                    return record, match_name
        return None, None

    def _pop_next(self, queue: deque[int] | None) -> ReplayRecord | None:
        if queue is None:
            return None
        while queue:
            index = queue[0]
            if index in self._consumed:
                queue.popleft()
                continue
            queue.popleft()
            self._consumed.add(index)
            return self._records_by_index[index]
        return None


class ReplayServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler_cls: type[BaseHTTPRequestHandler],
        *,
        matcher: ReplayMatcher,
        verbose: bool,
    ) -> None:
        super().__init__(server_address, handler_cls)
        self.matcher = matcher
        self.verbose = verbose


class ReplayRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CDPReplayServer/1.0"

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def do_PUT(self) -> None:
        self._handle_request()

    def do_PATCH(self) -> None:
        self._handle_request()

    def do_DELETE(self) -> None:
        self._handle_request()

    def do_OPTIONS(self) -> None:
        self._handle_request()

    def do_HEAD(self) -> None:
        self._handle_request()

    def _handle_request(self) -> None:
        content_length = self.headers.get("Content-Length")
        body_length = int(content_length) if content_length else 0
        body = self.rfile.read(body_length) if body_length else b""
        original_url = self.headers.get("X-Replay-Original-URL")
        matcher: ReplayMatcher = self.server.matcher  # type: ignore[attr-defined]
        record, match_name = matcher.match(
            method=self.command,
            path_query=self.path,
            original_url=original_url,
            body=body,
        )

        if record is None:
            self._send_not_found(body=body, original_url=original_url)
            return

        headers = sanitize_response_headers(record.response_headers, record.response_body)
        self.send_response(record.response_status or 500, record.response_reason)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("X-Replay-Match", match_name or "unknown")
        self.send_header("X-Replay-Record-Index", str(record.index))
        self.send_header("X-Replay-Original-URL", record.url)
        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(record.response_body)

        if self.server.verbose:  # type: ignore[attr-defined]
            print(
                f"[server] {match_name or '?'} {self.command} {self.path} -> "
                f"{record.response_status} [{record.index}]"
            )

    def _send_not_found(self, *, body: bytes, original_url: str | None) -> None:
        payload = {
            "error": "no recorded response matched this request",
            "method": self.command,
            "path": self.path,
            "original_url": original_url,
            "body_sha256": sha256_hex(body),
        }
        payload_bytes = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(404, "No Recorded Match")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload_bytes)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload_bytes)

        if self.server.verbose:  # type: ignore[attr-defined]
            print(f"[server] miss {self.command} {self.path}")

    def log_message(self, format: str, *args: Any) -> None:
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(format, *args)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("capture", help="path to the capture JSONL file")
    parser.add_argument("--host", default="127.0.0.1", help="listen address")
    parser.add_argument("--port", type=int, default=8080, help="listen port")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress per-request logs",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cdp-replay server",
        description=DESCRIPTION,
    )
    add_arguments(parser)
    return parser.parse_args(argv)


def main(args: argparse.Namespace) -> int:
    records, skipped = load_replay_records(args.capture, require_response_status=True)
    matcher = ReplayMatcher(records)
    server = ReplayServer(
        (args.host, args.port),
        ReplayRequestHandler,
        matcher=matcher,
        verbose=not args.quiet,
    )

    print(
        f"[server] loaded {len(records)} replayable records from {args.capture}"
        f" (skipped {skipped})"
    )
    print(f"[server] listening on http://{args.host}:{args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] stopping")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(parse_args()))
