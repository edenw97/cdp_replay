#!/usr/bin/env python3
"""Replay recorded HTTP responses from a CDP capture file."""

from __future__ import annotations

import argparse
import json
import ssl
import threading
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .common import (
    ReplayRecord,
    load_replay_records,
    sanitize_response_headers,
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
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(server_address, handler_cls)
        self.matcher = matcher
        self.verbose = verbose
        if tls_context is not None:
            self.socket = tls_context.wrap_socket(self.socket, server_side=True)


def build_tls_context(cert: str | None, key: str | None) -> ssl.SSLContext | None:
    if cert is None and key is None:
        return None
    if cert is None or key is None:
        raise ValueError("--tls-cert and --tls-key must be provided together")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["h2", "http/1.1"])
    return context


class ReplayRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CDPReplayServer/1.0"

    def handle(self) -> None:
        if self._negotiated_h2():
            self._serve_h2()
        else:
            super().handle()

    def _negotiated_h2(self) -> bool:
        if not H2_AVAILABLE:
            return False
        connection = self.connection
        if isinstance(connection, ssl.SSLSocket):
            return connection.selected_alpn_protocol() == "h2"
        return False

    def _serve_h2(self) -> None:
        self.close_connection = True
        connection = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        connection.initiate_connection()
        pending: dict[int, list] = {}
        request_headers: dict[int, list[tuple[str, str]]] = {}
        request_bodies: dict[int, bytearray] = {}
        try:
            self.connection.sendall(connection.data_to_send())
            while True:
                data = self.connection.recv(65536)
                if not data:
                    break
                try:
                    events = connection.receive_data(data)
                except h2.exceptions.H2Error as exc:
                    if self.server.verbose:  # type: ignore[attr-defined]
                        print(f"[server] h2 protocol error: {exc}")
                    break
                try:
                    for event in events:
                        if not self._h2_handle_event(
                            connection, event, pending, request_headers, request_bodies
                        ):
                            return
                except h2.exceptions.H2Error as exc:
                    if self.server.verbose:  # type: ignore[attr-defined]
                        print(f"[server] h2 protocol error: {exc}")
                    break
                out = connection.data_to_send()
                if out:
                    self.connection.sendall(out)
        except OSError:
            pass
        finally:
            try:
                out = connection.data_to_send()
                if out:
                    self.connection.sendall(out)
            except OSError:
                pass

    def _h2_handle_event(
        self,
        connection: h2.connection.H2Connection,
        event: Any,
        pending: dict[int, list],
        request_headers: dict[int, list[tuple[str, str]]],
        request_bodies: dict[int, bytearray],
    ) -> bool:
        if isinstance(event, h2.events.RequestReceived):
            request_headers[event.stream_id] = list(event.headers)
            if event.stream_ended:
                self._h2_respond(connection, event.stream_id, request_headers, request_bodies, pending)
        elif isinstance(event, h2.events.DataReceived):
            body = request_bodies.setdefault(event.stream_id, bytearray())
            body += event.data
            connection.acknowledge_received_data(
                event.flow_controlled_length, event.stream_id
            )
            if event.stream_ended:
                self._h2_respond(connection, event.stream_id, request_headers, request_bodies, pending)
        elif isinstance(event, h2.events.WindowUpdated):
            if event.stream_id == 0:
                for stream_id in list(pending):
                    self._h2_flush(connection, stream_id, pending)
            else:
                self._h2_flush(connection, event.stream_id, pending)
        elif isinstance(event, h2.events.RemoteSettingsChanged):
            for stream_id in list(pending):
                self._h2_flush(connection, stream_id, pending)
        elif isinstance(event, h2.events.ConnectionTerminated):
            return False
        elif isinstance(event, h2.events.PingReceived):
            connection.ping_ack(event.ping_data)
        elif isinstance(event, h2.events.StreamReset):
            pending.pop(event.stream_id, None)
            request_headers.pop(event.stream_id, None)
            request_bodies.pop(event.stream_id, None)
        return True

    def _h2_respond(
        self,
        connection: h2.connection.H2Connection,
        stream_id: int,
        request_headers: dict[int, list[tuple[str, str]]],
        request_bodies: dict[int, bytearray],
        pending: dict[int, list],
    ) -> None:
        headers = request_headers.pop(stream_id, [])
        body = bytes(request_bodies.pop(stream_id, bytearray()))
        method = ""
        path_query = ""
        original_url: str | None = None
        for name, value in headers:
            if name == ":method":
                method = value
            elif name == ":path":
                path_query = value
            elif name.lower() == "x-replay-original-url":
                original_url = value

        matcher: ReplayMatcher = self.server.matcher  # type: ignore[attr-defined]
        record, match_name = matcher.match(
            method=method,
            path_query=path_query,
            original_url=original_url,
            body=body,
        )

        verbose = self.server.verbose  # type: ignore[attr-defined]
        if record is None:
            payload = {
                "error": "no recorded response matched this request",
                "method": method,
                "path": path_query,
                "original_url": original_url,
                "body_sha256": sha256_hex(body),
            }
            payload_bytes = json.dumps(payload, indent=2).encode("utf-8")
            response_body = b"" if method == "HEAD" else payload_bytes
            response_headers = [
                (":status", "404"),
                ("content-type", "application/json"),
                ("content-length", str(len(payload_bytes))),
            ]
            connection.send_headers(stream_id, response_headers, end_stream=not response_body)
            if response_body:
                pending[stream_id] = [memoryview(response_body), 0]
                self._h2_flush(connection, stream_id, pending)
            if verbose:
                print(f"[server] miss {method} {path_query}")
            return

        sanitized = sanitize_response_headers(record.response_headers, record.response_body, http2=True)
        response_headers = [(":status", str(record.response_status or 500))]
        for name, value in sanitized.items():
            for piece in split_header_value(value):
                response_headers.append((name.lower(), piece))
        response_headers.append(("x-replay-match", match_name or "unknown"))
        response_headers.append(("x-replay-record-index", str(record.index)))
        response_headers.append(("x-replay-original-url", record.url))
        response_body = b"" if method == "HEAD" else record.response_body
        connection.send_headers(stream_id, response_headers, end_stream=not response_body)
        if response_body:
            pending[stream_id] = [memoryview(response_body), 0]
            self._h2_flush(connection, stream_id, pending)
        if verbose:
            print(
                f"[server] {match_name or '?'} {method} {path_query} -> "
                f"{record.response_status} [{record.index}]"
            )

    def _h2_flush(
        self,
        connection: h2.connection.H2Connection,
        stream_id: int,
        pending: dict[int, list],
    ) -> None:
        entry = pending.get(stream_id)
        if entry is None:
            return
        payload, offset = entry
        try:
            while offset < len(payload):
                window = connection.local_flow_control_window(stream_id)
                chunk = min(
                    window,
                    connection.max_outbound_frame_size,
                    len(payload) - offset,
                )
                if chunk <= 0:
                    break
                end_stream = offset + chunk == len(payload)
                connection.send_data(
                    stream_id,
                    payload[offset : offset + chunk],
                    end_stream=end_stream,
                )
                offset += chunk
        except h2.exceptions.H2Error:
            pending.pop(stream_id, None)
            return
        if offset >= len(payload):
            pending.pop(stream_id, None)
        else:
            entry[1] = offset

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
        "--tls-cert",
        default=None,
        help="path to the TLS certificate PEM (enables HTTPS with ALPN h2/http1.1)",
    )
    parser.add_argument(
        "--tls-key",
        default=None,
        help="path to the TLS private key PEM",
    )
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
    try:
        tls_context = build_tls_context(args.tls_cert, args.tls_key)
    except (ValueError, OSError, ssl.SSLError) as exc:
        print(f"[server] {exc}")
        return 2

    records, skipped = load_replay_records(args.capture, require_response_status=True)
    matcher = ReplayMatcher(records)
    server = ReplayServer(
        (args.host, args.port),
        ReplayRequestHandler,
        matcher=matcher,
        verbose=not args.quiet,
        tls_context=tls_context,
    )

    print(
        f"[server] loaded {len(records)} replayable records from {args.capture}"
        f" (skipped {skipped})"
    )
    scheme = "https" if tls_context is not None else "http"
    if tls_context is not None:
        print(f"[server] listening on {scheme}://{args.host}:{args.port} (HTTP/1.1 + HTTP/2 via ALPN)")
    else:
        print(f"[server] listening on {scheme}://{args.host}:{args.port} (HTTP/1.1 only)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] stopping")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(parse_args()))
