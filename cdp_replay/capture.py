#!/usr/bin/env python3
"""Capture HTTP request/response headers and bodies from Chrome via CDP."""

from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_BROWSER_HOST = "127.0.0.1"
DEFAULT_BROWSER_PORT = 9222
DEFAULT_URL = "about:blank"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_TOTAL_BUFFER_SIZE = 100_000_000
DEFAULT_MAX_RESOURCE_BUFFER_SIZE = 10_000_000
DEFAULT_MAX_POST_DATA_SIZE = 10_000_000
DEFAULT_RECONNECT_INTERVAL = 1.0
DEFAULT_STALLED_AFTER = 10.0
WEBSOCKET_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DEFAULT_MAX_WS_FRAMES = 20_000
WS_OPCODE_NAMES = {
    0: "continuation",
    1: "text",
    2: "binary",
    8: "close",
    9: "ping",
    10: "pong",
}


class CDPError(RuntimeError):
    """A CDP call returned an error."""


@dataclass
class BrowserProcess:
    process: subprocess.Popen[Any]
    user_data_dir: str | None


@dataclass
class SessionInfo:
    session_id: str
    target_id: str
    target_type: str
    title: str = ""
    url: str = ""


def parse_sse_events(text: str) -> list[dict[str, Any]]:
    """Parse a Server-Sent Events stream into a list of events.

    Each returned event is ``{"event": name, "id": id, "data": data}``.
    Consecutive ``data:`` lines are joined with ``\\n`` as required by the
    SSE specification; comment lines (``: keep-alive``) are ignored.
    """
    events: list[dict[str, Any]] = []
    event_name = ""
    event_id: str | None = None
    data_lines: list[str] = []

    def flush() -> None:
        nonlocal event_name, event_id, data_lines
        if data_lines or event_name or event_id is not None:
            events.append(
                {
                    "event": event_name or "message",
                    "id": event_id,
                    "data": "\n".join(data_lines),
                }
            )
        event_name = ""
        event_id = None
        data_lines = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line:
            flush()
            continue
        if line.startswith(":"):
            # Comment / keep-alive line.
            continue
        field, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if field == "event":
            event_name = value
        elif field == "data":
            data_lines.append(value)
        elif field == "id":
            event_id = value
        # "retry" and unknown fields are intentionally ignored.
    flush()
    return events


DESCRIPTION = (
    "Capture HTTP request/response headers and bodies from Chrome using the "
    "Chrome DevTools Protocol. The command can attach to an existing Chrome "
    "started with --remote-debugging-port, or launch a dedicated browser "
    "instance for you."
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=(
            "initial URL opened in a new page target after CDP capture is enabled "
            f"(default: {DEFAULT_URL})"
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        help="path to the JSONL output file (default: cdp_capture_<timestamp>.jsonl)",
    )
    parser.add_argument(
        "--browser-host",
        default=DEFAULT_BROWSER_HOST,
        help=f"remote debugging host (default: {DEFAULT_BROWSER_HOST})",
    )
    parser.add_argument(
        "--browser-port",
        type=int,
        default=DEFAULT_BROWSER_PORT,
        help=f"remote debugging port (default: {DEFAULT_BROWSER_PORT})",
    )
    parser.add_argument(
        "--browser-path",
        default=None,
        help="path to the Chrome/Chromium executable used when launching a browser",
    )
    parser.add_argument(
        "--user-data-dir",
        default=None,
        help="Chrome user-data-dir for a launched browser (default: a temporary directory)",
    )
    parser.add_argument(
        "--attach-only",
        action="store_true",
        help="only attach to an existing Chrome instance; do not launch a browser",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="launch Chrome in headless mode when a new browser is started",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"CDP/network timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--max-total-buffer-size",
        type=int,
        default=DEFAULT_MAX_TOTAL_BUFFER_SIZE,
        help=(
            "Network.enable maxTotalBufferSize passed to CDP "
            f"(default: {DEFAULT_MAX_TOTAL_BUFFER_SIZE})"
        ),
    )
    parser.add_argument(
        "--max-resource-buffer-size",
        type=int,
        default=DEFAULT_MAX_RESOURCE_BUFFER_SIZE,
        help=(
            "Network.enable maxResourceBufferSize passed to CDP "
            f"(default: {DEFAULT_MAX_RESOURCE_BUFFER_SIZE})"
        ),
    )
    parser.add_argument(
        "--max-post-data-size",
        type=int,
        default=DEFAULT_MAX_POST_DATA_SIZE,
        help=(
            "Network.enable maxPostDataSize passed to CDP "
            f"(default: {DEFAULT_MAX_POST_DATA_SIZE})"
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress live request summaries printed to stdout",
    )
    parser.add_argument(
        "--stalled-after",
        type=float,
        default=DEFAULT_STALLED_AFTER,
        help=(
            "log requests that started but did not finish within this many seconds "
            f"(default: {DEFAULT_STALLED_AFTER}, 0 disables)"
        ),
    )



def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cdp-replay capture",
        description=DESCRIPTION,
    )
    add_arguments(parser)
    return parser.parse_args(argv)


def build_default_output_path() -> str:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    return os.path.abspath(f"cdp_capture_{stamp}.jsonl")


def find_browser_executable(explicit_path: str | None) -> str | None:
    if explicit_path:
        return explicit_path

    candidates = [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
    ]
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def http_get_json(url: str, timeout: float) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = response.read()
    return json.loads(payload.decode("utf-8"))


def try_get_browser_version(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    endpoint = f"http://{host}:{port}/json/version"
    try:
        return http_get_json(endpoint, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, json.JSONDecodeError):
        return None


def wait_for_browser_endpoint(host: str, port: int, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        info = try_get_browser_version(host, port, timeout=min(1.0, timeout))
        if info:
            return info
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Timed out waiting for Chrome remote debugging endpoint at {host}:{port}"
            )
        time.sleep(0.25)


def wait_for_browser_endpoint_after_disconnect(
    host: str,
    port: int,
    *,
    poll_interval: float,
    quiet: bool,
    browser_process: BrowserProcess | None,
) -> dict[str, Any]:
    announced_wait = False
    while True:
        info = try_get_browser_version(host, port, timeout=1.0)
        if info:
            if announced_wait and not quiet:
                print("[cdp] browser debugging endpoint is back")
            return info

        if browser_process is not None and browser_process.process.poll() is not None:
            raise RuntimeError("Launched Chrome process exited while waiting to reconnect")

        if not announced_wait and not quiet:
            print("[cdp] waiting for the browser debugging endpoint to come back")
            announced_wait = True
        time.sleep(poll_interval)


def launch_browser(args: argparse.Namespace) -> BrowserProcess:
    browser_path = find_browser_executable(args.browser_path)
    if not browser_path:
        raise FileNotFoundError(
            "Could not find a Chrome/Chromium executable. Re-run with --browser-path "
            "or launch Chrome manually with --remote-debugging-port and use --attach-only."
        )

    user_data_dir = args.user_data_dir or tempfile.mkdtemp(prefix="cdp-capture-")
    command = [
        browser_path,
        f"--remote-debugging-address={args.browser_host}",
        f"--remote-debugging-port={args.browser_port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--disable-component-update",
        DEFAULT_URL,
    ]
    if args.headless:
        command.insert(-1, "--headless=new")

    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return BrowserProcess(process=process, user_data_dir=user_data_dir)


class WebSocketClient:
    """Minimal WebSocket client for talking to a local CDP endpoint."""

    def __init__(self, uri: str, timeout: float) -> None:
        self.uri = uri
        self.timeout = timeout
        self._recv_buffer = bytearray()
        self._closed = False

        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme != "ws":
            raise ValueError(f"Only ws:// URIs are supported, got {uri!r}")
        if not parsed.hostname:
            raise ValueError(f"WebSocket URI is missing a hostname: {uri!r}")

        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(timeout)
        self._perform_handshake(host, port, path)

    def _perform_handshake(self, host: str, port: int, path: str) -> None:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        expected_accept = base64.b64encode(
            hashlib.sha1(f"{key}{WEBSOCKET_MAGIC}".encode("ascii")).digest()
        ).decode("ascii")

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self._sock.sendall(request.encode("ascii"))

        raw_headers = self._read_until(b"\r\n\r\n")
        head, _, rest = raw_headers.partition(b"\r\n\r\n")
        if rest:
            self._recv_buffer.extend(rest)

        lines = head.decode("iso-8859-1").split("\r\n")
        if not lines or " 101 " not in f" {lines[0]} ":
            raise ConnectionError(f"WebSocket upgrade failed: {lines[0] if lines else head!r}")

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        if headers.get("sec-websocket-accept") != expected_accept:
            raise ConnectionError("WebSocket handshake returned an unexpected Sec-WebSocket-Accept")

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self._recv_buffer:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise EOFError("Socket closed while waiting for WebSocket handshake")
            self._recv_buffer.extend(chunk)
        index = self._recv_buffer.index(marker) + len(marker)
        data = bytes(self._recv_buffer[:index])
        del self._recv_buffer[:index]
        return data

    def _recv_exact(self, size: int, timeout: float | None = None) -> bytes:
        previous_timeout = self._sock.gettimeout()
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            while len(self._recv_buffer) < size:
                try:
                    chunk = self._sock.recv(4096)
                except socket.timeout as exc:
                    raise TimeoutError("Timed out waiting for a WebSocket frame") from exc
                if not chunk:
                    raise EOFError("Socket closed while reading WebSocket frame")
                self._recv_buffer.extend(chunk)
            data = bytes(self._recv_buffer[:size])
            del self._recv_buffer[:size]
            return data
        finally:
            if timeout is not None:
                self._sock.settimeout(previous_timeout)

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if self._closed:
            return

        mask_key = secrets.token_bytes(4)
        masked_payload = bytes(
            byte ^ mask_key[index % 4] for index, byte in enumerate(payload)
        )

        header = bytearray()
        header.append(0x80 | opcode)
        payload_length = len(payload)
        if payload_length < 126:
            header.append(0x80 | payload_length)
        elif payload_length < (1 << 16):
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", payload_length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", payload_length))
        header.extend(mask_key)
        self._sock.sendall(bytes(header) + masked_payload)

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def _read_frame(self, timeout: float | None = None) -> tuple[bool, int, bytes]:
        header = self._recv_exact(2, timeout=timeout)
        first_byte, second_byte = header
        fin = bool(first_byte & 0x80)
        opcode = first_byte & 0x0F
        masked = bool(second_byte & 0x80)
        payload_length = second_byte & 0x7F

        if payload_length == 126:
            payload_length = struct.unpack("!H", self._recv_exact(2, timeout=timeout))[0]
        elif payload_length == 127:
            payload_length = struct.unpack("!Q", self._recv_exact(8, timeout=timeout))[0]

        mask_key = self._recv_exact(4, timeout=timeout) if masked else b""
        payload = self._recv_exact(payload_length, timeout=timeout) if payload_length else b""
        if masked:
            payload = bytes(
                byte ^ mask_key[index % 4] for index, byte in enumerate(payload)
            )
        return fin, opcode, payload

    def recv_text(self, timeout: float | None = None) -> str | None:
        fragments: list[bytes] = []
        opcode: int | None = None

        while True:
            fin, frame_opcode, payload = self._read_frame(timeout=timeout)

            if frame_opcode == 0x8:
                self._closed = True
                return None
            if frame_opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if frame_opcode == 0xA:
                continue

            if frame_opcode == 0x0:
                if opcode is None:
                    raise ConnectionError("Received unexpected continuation frame")
            else:
                if opcode is not None:
                    raise ConnectionError("Received a new data frame before the previous one finished")
                opcode = frame_opcode

            fragments.append(payload)
            if not fin:
                continue

            message = b"".join(fragments)
            if opcode != 0x1:
                raise ConnectionError(f"Expected a text frame from CDP, got opcode {opcode}")
            return message.decode("utf-8")

    def close(self) -> None:
        if self._closed:
            return
        with contextlib.suppress(OSError):
            self._send_frame(0x8, b"")
        self._closed = True
        with contextlib.suppress(OSError):
            self._sock.close()


class CDPClient:
    """Send commands and receive events over a CDP WebSocket."""

    def __init__(self, websocket_url: str, timeout: float) -> None:
        self.timeout = timeout
        self._ws = WebSocketClient(websocket_url, timeout=timeout)
        self._next_id = 1
        self._pending_responses: dict[int, dict[str, Any]] = {}
        self._events: collections.deque[dict[str, Any]] = collections.deque()

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        message_id = self._next_id
        self._next_id += 1

        message: dict[str, Any] = {
            "id": message_id,
            "method": method,
            "params": params or {},
        }
        if session_id:
            message["sessionId"] = session_id

        self._ws.send_text(json.dumps(message))
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)

        while True:
            response = self._pending_responses.pop(message_id, None)
            if response is not None:
                if "error" in response:
                    error = response["error"]
                    raise CDPError(
                        f"{method} failed with code {error.get('code')}: {error.get('message')}"
                    )
                return response.get("result", {})

            self._pump(deadline)

    def next_event(self, timeout: float | None = None) -> dict[str, Any]:
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._events:
            self._pump(deadline)
        return self._events.popleft()

    def _pump(self, deadline: float | None) -> None:
        remaining = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for a CDP message")

        payload = self._ws.recv_text(timeout=remaining)
        if payload is None:
            raise EOFError("CDP WebSocket closed")

        message = json.loads(payload)
        if "id" in message:
            self._pending_responses[message["id"]] = message
        else:
            self._events.append(message)

    def close(self) -> None:
        self._ws.close()


class CaptureRecorder:
    """Convert CDP network events into one JSONL record per request."""

    def __init__(
        self,
        client: CDPClient,
        output_path: str,
        *,
        quiet: bool,
        network_enable_params: dict[str, Any],
    ) -> None:
        self.client = client
        self.output_path = output_path
        self.quiet = quiet
        self.network_enable_params = network_enable_params
        self.sessions: dict[str, SessionInfo] = {}
        self.enabled_sessions: set[str] = set()
        self.target_to_session: dict[str, str] = {}
        self.records: dict[tuple[str | None, str], dict[str, Any]] = {}
        self._output = open(output_path, "w", encoding="utf-8")
        # SSE (text/event-stream) bodies are not available through
        # Network.getResponseBody; they are pulled with
        # Network.streamResourceContent while the stream is live.
        self._sse_buffers: dict[tuple[str | None, str], bytearray] = {}
        self._sse_stream_content_disabled = False

    def close(self, *, failure_reason: str | None = None) -> None:
        self.flush_pending(incomplete=True, failure_reason=failure_reason)
        self._output.close()

    def bind_client(self, client: CDPClient) -> None:
        self.client = client

    def handle_browser_disconnect(self, reason: str) -> None:
        pending = list(self.records.values())
        self.records.clear()
        for record in pending:
            record["incomplete"] = True
            record["failure"] = {
                "errorText": reason,
            }
            self._write_record(record)
        self._clear_session_state()

    def handle_event(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        params = message.get("params", {})
        session_id = message.get("sessionId")

        if method == "Target.attachedToTarget":
            self._handle_attached_to_target(params)
            return
        if method == "Target.detachedFromTarget":
            self._handle_detached_from_target(params)
            return
        if method == "Target.targetInfoChanged":
            self._handle_target_info_changed(params)
            return
        if method == "Target.targetDestroyed":
            self._handle_target_destroyed(params)
            return
        if method == "Network.requestWillBeSent":
            self._handle_request_will_be_sent(session_id, params)
            return
        if method == "Network.requestWillBeSentExtraInfo":
            self._handle_request_will_be_sent_extra_info(session_id, params)
            return
        if method == "Network.responseReceived":
            self._handle_response_received(session_id, params)
            return
        if method == "Network.responseReceivedExtraInfo":
            self._handle_response_received_extra_info(session_id, params)
            return
        if method == "Network.requestServedFromCache":
            self._handle_request_served_from_cache(session_id, params)
            return
        if method == "Network.loadingFinished":
            self._handle_loading_finished(session_id, params)
            return
        if method == "Network.loadingFailed":
            self._handle_loading_failed(session_id, params)
            return
        if method == "Network.dataReceived":
            self._handle_data_received(session_id, params)
            return
        if method == "Network.eventSourceMessageReceived":
            self._handle_event_source_message(session_id, params)
            return
        if method == "Network.webSocketCreated":
            self._handle_ws_created(session_id, params)
            return
        if method == "Network.webSocketWillSendHandshakeRequest":
            self._handle_ws_handshake_request(session_id, params)
            return
        if method == "Network.webSocketHandshakeResponseReceived":
            self._handle_ws_handshake_response(session_id, params)
            return
        if method == "Network.webSocketFrameSent":
            self._handle_ws_frame(session_id, params, direction="sent")
            return
        if method == "Network.webSocketFrameReceived":
            self._handle_ws_frame(session_id, params, direction="received")
            return
        if method == "Network.webSocketFrameError":
            self._handle_ws_error(session_id, params)
            return
        if method == "Network.webSocketClosed":
            self._handle_ws_closed(session_id, params)
            return

    def ensure_session_enabled(self, session_id: str, target_info: dict[str, Any]) -> None:
        target_type = target_info.get("type", "")
        target_id = target_info.get("targetId", "")
        info = self.sessions.get(session_id)
        if info is None:
            info = SessionInfo(
                session_id=session_id,
                target_id=target_id,
                target_type=target_type,
                title=target_info.get("title", ""),
                url=target_info.get("url", ""),
            )
            self.sessions[session_id] = info
        else:
            info.target_id = target_id or info.target_id
            info.target_type = target_type or info.target_type
            info.title = target_info.get("title", info.title)
            info.url = target_info.get("url", info.url)

        if info.target_id:
            self.target_to_session[info.target_id] = session_id

        if target_type != "page" or session_id in self.enabled_sessions:
            return

        self.client.call("Page.enable", session_id=session_id)
        self.client.call(
            "Network.enable",
            params=self.network_enable_params,
            session_id=session_id,
        )
        self.enabled_sessions.add(session_id)
        if not self.quiet:
            target_label = info.url or info.title or info.target_id
            print(f"[cdp] attached to page session {session_id} ({target_label})")

    def flush_pending(
        self,
        *,
        incomplete: bool,
        failure_reason: str | None = None,
    ) -> None:
        pending = list(self.records.values())
        self.records.clear()
        for record in pending:
            if incomplete:
                record["incomplete"] = True
            if failure_reason is not None:
                record["failure"] = {
                    "errorText": failure_reason,
                }
            self._write_record(record)

    def check_stalled_requests(self, stalled_after_seconds: float) -> None:
        if stalled_after_seconds <= 0:
            return

        now_wall_time = time.time()
        for record in self._iter_pending_records():
            if record.get("stall_logged"):
                continue
            if record.get("resource_type") == "WebSocket":
                # Sockets stay open by design; not a stalled request.
                continue

            timing = record.get("timing", {})
            started_at = timing.get("wall_time")
            if not isinstance(started_at, (int, float)):
                continue

            age_seconds = now_wall_time - started_at
            if age_seconds < stalled_after_seconds:
                continue

            record["stall_logged"] = True
            record["stalled"] = {
                "reported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "age_seconds": round(age_seconds, 3),
                "threshold_seconds": stalled_after_seconds,
            }
            print(
                "[stalled] "
                + self._format_pending_record(
                    record,
                    age_seconds=age_seconds,
                )
            )

    def print_inflight_requests(self, *, reason: str) -> None:
        pending = self._iter_pending_records()
        count = len(pending)
        print(f"[cdp] {reason}; {count} request(s) still in flight")
        for record in pending:
            print("[inflight] " + self._format_pending_record(record))

    def _handle_attached_to_target(self, params: dict[str, Any]) -> None:
        session_id = params["sessionId"]
        target_info = params.get("targetInfo", {})
        self.ensure_session_enabled(session_id, target_info)

    def _handle_detached_from_target(self, params: dict[str, Any]) -> None:
        session_id = params.get("sessionId")
        if not session_id:
            return

        related_keys = [key for key in self.records if key[0] == session_id]
        for key in related_keys:
            record = self.records.pop(key)
            record["incomplete"] = True
            record["failure"] = {
                "errorText": "Target detached before request completed",
            }
            self._write_record(record)

        info = self.sessions.pop(session_id, None)
        self.enabled_sessions.discard(session_id)
        if info and info.target_id:
            self.target_to_session.pop(info.target_id, None)

    def _handle_target_info_changed(self, params: dict[str, Any]) -> None:
        target_info = params.get("targetInfo", {})
        target_id = target_info.get("targetId")
        if not target_id:
            return
        session_id = self.target_to_session.get(target_id)
        if not session_id:
            return
        info = self.sessions.get(session_id)
        if not info:
            return
        info.title = target_info.get("title", info.title)
        info.url = target_info.get("url", info.url)
        info.target_type = target_info.get("type", info.target_type)

    def _handle_target_destroyed(self, params: dict[str, Any]) -> None:
        target_id = params.get("targetId")
        if not target_id:
            return
        session_id = self.target_to_session.pop(target_id, None)
        if session_id:
            self.sessions.pop(session_id, None)
            self.enabled_sessions.discard(session_id)

    def _get_or_create_record(self, session_id: str | None, request_id: str) -> dict[str, Any]:
        key = (session_id, request_id)
        record = self.records.get(key)
        if record is None:
            session_info = self.sessions.get(session_id or "")
            record = {
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "session": {
                    "session_id": session_id,
                    "target_id": session_info.target_id if session_info else None,
                    "target_type": session_info.target_type if session_info else None,
                    "target_title": session_info.title if session_info else None,
                    "target_url": session_info.url if session_info else None,
                },
                "request_id": request_id,
            }
            self.records[key] = record
        return record

    def _handle_request_will_be_sent(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        request_id = params["requestId"]
        key = (session_id, request_id)

        redirect_response = params.get("redirectResponse")
        if redirect_response and key in self.records:
            record = self.records.pop(key)
            response = record.setdefault("response", {})
            self._merge_response_payload(response, redirect_response)
            response["body_error"] = "Response body unavailable for redirect hop"
            record["redirected_to"] = params.get("request", {}).get("url")
            self._write_record(record)

        record = self._get_or_create_record(session_id, request_id)
        record["loader_id"] = params.get("loaderId")
        record["frame_id"] = params.get("frameId")
        record["resource_type"] = params.get("type")
        record["document_url"] = params.get("documentURL")
        timing = record.setdefault("timing", {})
        timing["timestamp"] = params.get("timestamp")
        timing["wall_time"] = params.get("wallTime")
        if "initiator" in params:
            record["initiator"] = params["initiator"]

        request = record.setdefault("request", {})
        payload = params.get("request", {})
        request["url"] = payload.get("url")
        request["method"] = payload.get("method")
        request["headers"] = payload.get("headers", {})
        request["mixed_content_type"] = payload.get("mixedContentType")
        request["initial_priority"] = payload.get("initialPriority")
        request["referrer_policy"] = payload.get("referrerPolicy")
        request["has_post_data"] = payload.get("hasPostData", False)
        if "postData" in payload:
            request["body"] = {
                "text": payload["postData"],
                "base64Encoded": False,
            }

    def _handle_request_will_be_sent_extra_info(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        record = self._get_or_create_record(session_id, params["requestId"])
        request = record.setdefault("request", {})
        request["extra_headers"] = params.get("headers", {})
        if "headersText" in params:
            request["headers_text"] = params["headersText"]
        if "associatedCookies" in params:
            request["associated_cookies"] = params["associatedCookies"]
        if "connectTiming" in params:
            request["connect_timing"] = params["connectTiming"]
        if "siteHasCookieInOtherPartition" in params:
            request["site_has_cookie_in_other_partition"] = params[
                "siteHasCookieInOtherPartition"
            ]

    def _handle_response_received(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        record = self._get_or_create_record(session_id, params["requestId"])
        record["resource_type"] = params.get("type", record.get("resource_type"))
        if "request" not in record:
            record["late_attach"] = True
        response = record.setdefault("response", {})
        self._merge_response_payload(response, params.get("response", {}))

    def _handle_response_received_extra_info(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        record = self._get_or_create_record(session_id, params["requestId"])
        if "request" not in record:
            record["late_attach"] = True
        response = record.setdefault("response", {})
        response["extra_headers"] = params.get("headers", {})
        if "headersText" in params:
            response["headers_text"] = params["headersText"]
        if "resourceIPAddressSpace" in params:
            response["resource_ip_address_space"] = params["resourceIPAddressSpace"]
        if "statusCode" in params:
            response["status_code_from_extra_info"] = params["statusCode"]
        if "blockedCookies" in params:
            response["blocked_cookies"] = params["blockedCookies"]

    def _handle_request_served_from_cache(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        record = self._get_or_create_record(session_id, params["requestId"])
        response = record.setdefault("response", {})
        response["served_from_cache"] = True

    def _handle_loading_finished(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        key = (session_id, params["requestId"])
        record = self.records.get(key)
        if record is None:
            return

        timing = record.setdefault("timing", {})
        timing["loading_finished_timestamp"] = params.get("timestamp")
        response = record.setdefault("response", {})
        response["encoded_data_length"] = params.get("encodedDataLength")

        if self._is_event_stream(response):
            self._drain_stream_content(record)

        self._maybe_fetch_request_body(record)
        self._maybe_fetch_response_body(record)
        self.records.pop(key, None)
        self._write_record(record)

    def _handle_loading_failed(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        key = (session_id, params["requestId"])
        record = self.records.get(key)
        if record is None:
            return

        timing = record.setdefault("timing", {})
        timing["loading_failed_timestamp"] = params.get("timestamp")
        record["failure"] = {
            "errorText": params.get("errorText"),
            "blockedReason": params.get("blockedReason"),
            "canceled": params.get("canceled"),
        }

        if self._is_event_stream(record.setdefault("response", {})):
            self._drain_stream_content(record)

        self._maybe_fetch_request_body(record)
        self.records.pop(key, None)
        self._write_record(record)

    @staticmethod
    def _is_event_stream(response: dict[str, Any]) -> bool:
        mime_type = (response.get("mime_type") or "").lower()
        if "event-stream" in mime_type:
            return True
        headers = response.get("headers") or {}
        for name, value in headers.items():
            if name.lower() == "content-type" and "event-stream" in (value or "").lower():
                return True
        return False

    def _handle_data_received(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        record = self.records.get((session_id, request_id))
        if record is None:
            return
        if not self._is_event_stream(record.get("response") or {}):
            return
        self._drain_stream_content(record)

    def _handle_event_source_message(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        # Fired for EventSource connections (not fetch()-based streams).
        request_id = params.get("requestId")
        if not request_id:
            return
        record = self.records.get((session_id, request_id))
        if record is None:
            return
        response = record.setdefault("response", {})
        messages = response.setdefault("event_source_messages", [])
        messages.append(
            {
                "timestamp": params.get("timestamp"),
                "event": params.get("eventName") or "message",
                "id": params.get("eventId"),
                "data": params.get("data", ""),
            }
        )

    def _get_or_create_ws_record(
        self,
        session_id: str | None,
        request_id: str,
    ) -> dict[str, Any]:
        record = self.records.get((session_id, request_id))
        if record is not None:
            record.setdefault(
                "websocket",
                {
                    "url": None,
                    "handshake_request": None,
                    "handshake_response": None,
                    "frames": [],
                    "frame_counts": {"sent": 0, "received": 0},
                    "dropped_frames": 0,
                    "closed": None,
                    "error": None,
                },
            )
            record["resource_type"] = "WebSocket"
            return record

        record = self._get_or_create_record(session_id, request_id)
        record["resource_type"] = "WebSocket"
        record["websocket"] = {
            "url": None,
            "handshake_request": None,
            "handshake_response": None,
            "frames": [],
            "frame_counts": {"sent": 0, "received": 0},
            "dropped_frames": 0,
            "closed": None,
            "error": None,
        }
        return record

    def _handle_ws_created(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        record = self._get_or_create_ws_record(session_id, request_id)
        websocket = record["websocket"]
        websocket["url"] = params.get("url")
        if params.get("initiator") is not None:
            record["initiator"] = params["initiator"]
        request = record.setdefault("request", {})
        request.setdefault("url", params.get("url"))
        request.setdefault("method", "GET")

    def _handle_ws_handshake_request(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        record = self._get_or_create_ws_record(session_id, request_id)
        websocket = record["websocket"]
        payload = params.get("request") or {}
        websocket["handshake_request"] = {
            "timestamp": params.get("timestamp"),
            "wall_time": params.get("wallTime"),
            "headers": payload.get("headers"),
            "headers_text": payload.get("headersText"),
        }
        request = record.setdefault("request", {})
        request["method"] = "GET"
        if websocket.get("url"):
            request["url"] = websocket["url"]
        request["headers"] = payload.get("headers", {})
        timing = record.setdefault("timing", {})
        timing.setdefault("timestamp", params.get("timestamp"))
        timing.setdefault("wall_time", params.get("wallTime"))

    def _handle_ws_handshake_response(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        record = self._get_or_create_ws_record(session_id, request_id)
        websocket = record["websocket"]
        payload = params.get("response") or {}
        websocket["handshake_response"] = {
            "timestamp": params.get("timestamp"),
            "status": payload.get("status"),
            "status_text": payload.get("statusText"),
            "headers": payload.get("headers"),
            "headers_text": payload.get("headersText"),
        }
        response = record.setdefault("response", {})
        response["status"] = payload.get("status")
        response["status_text"] = payload.get("statusText")
        response["headers"] = payload.get("headers", {})

    def _handle_ws_frame(
        self,
        session_id: str | None,
        params: dict[str, Any],
        *,
        direction: str,
    ) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        record = self.records.get((session_id, request_id))
        if record is None:
            return
        websocket = record.get("websocket")
        if not websocket:
            return
        payload = params.get("response") or {}
        opcode = payload.get("opcode")
        frame = {
            "direction": direction,
            "timestamp": params.get("timestamp"),
            "opcode": opcode,
            "opcode_name": WS_OPCODE_NAMES.get(opcode, str(opcode)),
            "payload_data": payload.get("payloadData", ""),
        }
        frames = websocket["frames"]
        if len(frames) < DEFAULT_MAX_WS_FRAMES:
            frames.append(frame)
            websocket["frame_counts"][direction] += 1
        else:
            websocket["dropped_frames"] += 1

    def _handle_ws_error(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        record = self.records.get((session_id, request_id))
        if record is None or "websocket" not in record:
            return
        record["websocket"]["error"] = {
            "timestamp": params.get("timestamp"),
            "message": params.get("errorMessage"),
        }

    def _handle_ws_closed(
        self,
        session_id: str | None,
        params: dict[str, Any],
    ) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        key = (session_id, request_id)
        record = self.records.pop(key, None)
        if record is None:
            return
        websocket = record.setdefault("websocket", {})
        websocket["closed"] = {"timestamp": params.get("timestamp")}
        self._write_record(record)

    def _drain_stream_content(self, record: dict[str, Any]) -> None:
        """Pull buffered bytes of a streaming response into the record.

        ``Network.getResponseBody`` does not return bodies of streaming
        resources (``text/event-stream``, ``fetch()`` streams). DevTools'
        EventStream panel uses ``Network.streamResourceContent`` instead; it
        must be called while the stream is alive and returns base64-encoded
        data buffered since the previous call.
        """
        if self._sse_stream_content_disabled:
            return
        request_id = record.get("request_id")
        if not request_id:
            return
        session_id = record.get("session", {}).get("session_id")
        response = record.setdefault("response", {})
        response["sse_stream"] = True
        try:
            result = self.client.call(
                "Network.streamResourceContent",
                {"requestId": request_id},
                session_id=session_id,
                timeout=2.0,
            )
        except CDPError as exc:
            message = str(exc).lower()
            if "method" in message and ("not found" in message or "invalid" in message):
                self._sse_stream_content_disabled = True
            return
        except (TimeoutError, EOFError, ConnectionError, OSError):
            return

        encoded = result.get("bufferedData")
        if not encoded:
            return
        try:
            chunk = base64.b64decode(encoded)
        except (ValueError, TypeError):
            return
        key = (session_id, request_id)
        buffer = self._sse_buffers.get(key)
        if buffer is None:
            self._sse_buffers[key] = bytearray(chunk)
            return
        existing = bytes(buffer)
        if chunk.startswith(existing):
            # streamResourceContent returns the content buffered so far;
            # keep only the new suffix.
            buffer.extend(chunk[len(existing):])
        elif existing.startswith(chunk):
            # Older/stale snapshot; nothing new.
            return
        else:
            buffer.extend(chunk)

    def _finalize_sse_body(self, record: dict[str, Any]) -> None:
        """Attach streamed SSE bytes as the record's response body."""
        response = record.get("response") or {}
        if not response:
            return
        key = (record.get("session", {}).get("session_id"), record.get("request_id"))
        buffer = self._sse_buffers.pop(key, None)
        if buffer is None and not self._is_event_stream(response):
            return

        buffered_text = bytes(buffer).decode("utf-8", "replace") if buffer else ""
        body = response.get("body") or {}
        if body.get("base64Encoded"):
            try:
                existing_text = base64.b64decode(body.get("base64", "")).decode(
                    "utf-8", "replace"
                )
            except (ValueError, TypeError):
                existing_text = ""
        else:
            existing_text = body.get("text") or ""

        # Prefer the most complete representation we have: getResponseBody()
        # may return the full body when the stream already finished, while
        # streamResourceContent() gives us the live chunks.
        if len(buffered_text) > len(existing_text):
            response["body"] = {
                "text": buffered_text,
                "base64Encoded": False,
            }
            response.pop("body_error", None)
            existing_text = buffered_text

        if existing_text:
            events = parse_sse_events(existing_text)
            if events:
                response["sse_events"] = events
                response["sse"] = True
        if response.get("event_source_messages") and "sse_events" not in response:
            response["sse_events"] = [
                {
                    "event": message.get("event") or "message",
                    "id": message.get("id"),
                    "data": message.get("data", ""),
                }
                for message in response["event_source_messages"]
            ]
            response["sse"] = True

    def _merge_response_payload(self, response: dict[str, Any], payload: dict[str, Any]) -> None:
        response["url"] = payload.get("url", response.get("url"))
        response["status"] = payload.get("status", response.get("status"))
        response["status_text"] = payload.get("statusText", response.get("status_text"))
        response["headers"] = payload.get("headers", response.get("headers", {}))
        response["mime_type"] = payload.get("mimeType", response.get("mime_type"))
        response["protocol"] = payload.get("protocol", response.get("protocol"))
        response["remote_ip_address"] = payload.get(
            "remoteIPAddress", response.get("remote_ip_address")
        )
        response["remote_port"] = payload.get("remotePort", response.get("remote_port"))
        response["from_disk_cache"] = payload.get(
            "fromDiskCache", response.get("from_disk_cache")
        )
        response["from_prefetch_cache"] = payload.get(
            "fromPrefetchCache", response.get("from_prefetch_cache")
        )
        response["from_service_worker"] = payload.get(
            "fromServiceWorker", response.get("from_service_worker")
        )
        response["security_state"] = payload.get(
            "securityState", response.get("security_state")
        )
        response["connection_reused"] = payload.get(
            "connectionReused", response.get("connection_reused")
        )
        response["connection_id"] = payload.get("connectionId", response.get("connection_id"))

    def _maybe_fetch_request_body(self, record: dict[str, Any]) -> None:
        request = record.get("request", {})
        if request.get("body") is not None:
            return
        if not request.get("has_post_data"):
            return

        try:
            result = self.client.call(
                "Network.getRequestPostData",
                {"requestId": record["request_id"]},
                session_id=record["session"]["session_id"],
                timeout=5.0,
            )
        except (CDPError, TimeoutError, EOFError, ConnectionError, OSError) as exc:
            request["body_error"] = str(exc)
            return

        request["body"] = {
            "text": result.get("postData", ""),
            "base64Encoded": False,
        }

    def _maybe_fetch_response_body(self, record: dict[str, Any]) -> None:
        response = record.setdefault("response", {})
        try:
            result = self.client.call(
                "Network.getResponseBody",
                {"requestId": record["request_id"]},
                session_id=record["session"]["session_id"],
                timeout=10.0,
            )
        except (CDPError, TimeoutError, EOFError, ConnectionError, OSError) as exc:
            response["body_error"] = str(exc)
            return

        if result.get("base64Encoded"):
            response["body"] = {
                "base64": result.get("body", ""),
                "base64Encoded": True,
            }
        else:
            response["body"] = {
                "text": result.get("body", ""),
                "base64Encoded": False,
            }

    def _write_record(self, record: dict[str, Any]) -> None:
        self._finalize_sse_body(record)
        session_id = record.get("session", {}).get("session_id")
        session_info = self.sessions.get(session_id or "")
        if session_info:
            record["session"]["target_id"] = session_info.target_id
            record["session"]["target_type"] = session_info.target_type
            record["session"]["target_title"] = session_info.title
            record["session"]["target_url"] = session_info.url

        self._output.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._output.flush()

        if self.quiet:
            return

        request = record.get("request", {})
        response = record.get("response", {})
        failure = record.get("failure")
        status = response.get("status")
        late_attach = bool(record.get("late_attach"))
        method = request.get("method")
        if not method:
            method = "GET?" if late_attach else "?"
        url = request.get("url")
        if not url:
            url = response.get("url")
        if not url:
            url = "<unknown>"

        if failure:
            state = failure.get("errorText", "FAILED")
        elif status is not None:
            state = str(status)
        else:
            state = "DONE"
        if late_attach:
            print(f"[capture] {state} [late-attach] {method} {url}")
        else:
            print(f"[capture] {state} {method} {url}")

    def _clear_session_state(self) -> None:
        self.sessions.clear()
        self.enabled_sessions.clear()
        self.target_to_session.clear()

    def _iter_pending_records(self) -> list[dict[str, Any]]:
        def sort_key(record: dict[str, Any]) -> float:
            timing = record.get("timing", {})
            started_at = timing.get("wall_time")
            if isinstance(started_at, (int, float)):
                return started_at
            return float("inf")

        return sorted(self.records.values(), key=sort_key)

    def _format_pending_record(
        self,
        record: dict[str, Any],
        *,
        age_seconds: float | None = None,
    ) -> str:
        request = record.get("request", {})
        response = record.get("response", {})
        session = record.get("session", {})
        initiator = record.get("initiator", {})
        timing = record.get("timing", {})

        if age_seconds is None:
            started_at = timing.get("wall_time")
            if isinstance(started_at, (int, float)):
                age_seconds = max(0.0, time.time() - started_at)

        method = request.get("method")
        if not method:
            method = "GET?" if record.get("late_attach") else "?"
        url = request.get("url") or response.get("url") or "<unknown>"

        parts = []
        if age_seconds is not None:
            parts.append(f"{age_seconds:.3f}s")
        parts.append(method)
        parts.append(url)

        status = response.get("status")
        if status is not None:
            parts.append(f"response_status={status}")
        if record.get("request_id"):
            parts.append(f"request_id={record['request_id']}")
        if session.get("session_id"):
            parts.append(f"session={session['session_id']}")
        if record.get("frame_id"):
            parts.append(f"frame={record['frame_id']}")
        target_url = session.get("target_url")
        if target_url:
            parts.append(f"target={target_url}")
        initiator_type = initiator.get("type")
        if initiator_type:
            parts.append(f"initiator={initiator_type}")
        initiator_url = initiator.get("url")
        if initiator_url:
            parts.append(f"initiator_url={initiator_url}")
        return " | ".join(parts)


def create_initial_target(client: CDPClient) -> str:
    result = client.call("Target.createTarget", {"url": DEFAULT_URL})
    return result["targetId"]


def attach_to_existing_page_targets(client: CDPClient, recorder: CaptureRecorder) -> None:
    result = client.call("Target.getTargets")
    for target_info in result.get("targetInfos", []):
        if target_info.get("type") != "page":
            continue
        if target_info.get("attached"):
            continue
        try:
            attach_result = client.call(
                "Target.attachToTarget",
                {
                    "targetId": target_info["targetId"],
                    "flatten": True,
                },
            )
        except CDPError:
            continue
        recorder.ensure_session_enabled(attach_result["sessionId"], target_info)


def wait_for_session_for_target(
    recorder: CaptureRecorder,
    client: CDPClient,
    target_id: str,
    timeout: float,
) -> str:
    deadline = time.monotonic() + timeout
    while True:
        session_id = recorder.target_to_session.get(target_id)
        if session_id:
            return session_id
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Timed out waiting for CDP session for target {target_id}")
        recorder.handle_event(client.next_event(timeout=remaining))


def drain_events_forever(
    recorder: CaptureRecorder,
    client: CDPClient,
    *,
    stalled_after_seconds: float,
) -> None:
    while True:
        try:
            event = client.next_event(timeout=1.0)
        except TimeoutError:
            recorder.check_stalled_requests(stalled_after_seconds)
            continue
        recorder.handle_event(event)
        recorder.check_stalled_requests(stalled_after_seconds)


def configure_capture_client(client: CDPClient, recorder: CaptureRecorder) -> None:
    client.call("Target.setDiscoverTargets", {"discover": True})
    client.call(
        "Target.setAutoAttach",
        {
            "autoAttach": True,
            "waitForDebuggerOnStart": False,
            "flatten": True,
        },
    )
    attach_to_existing_page_targets(client, recorder)


def get_browser_websocket_url(browser_info: dict[str, Any]) -> str:
    websocket_url = browser_info.get("webSocketDebuggerUrl")
    if not websocket_url:
        raise RuntimeError("Chrome did not expose a browser-level webSocketDebuggerUrl.")
    return websocket_url


def main(args: argparse.Namespace) -> int:
    output_path = os.path.abspath(args.output or build_default_output_path())
    network_enable_params = {
        "maxTotalBufferSize": args.max_total_buffer_size,
        "maxResourceBufferSize": args.max_resource_buffer_size,
        "maxPostDataSize": args.max_post_data_size,
    }

    browser_process: BrowserProcess | None = None
    browser_info = try_get_browser_version(args.browser_host, args.browser_port, timeout=1.0)
    if browser_info is None:
        if args.attach_only:
            print(
                "Chrome remote debugging endpoint is not reachable. Start Chrome with "
                f"--remote-debugging-port={args.browser_port} and retry.",
                file=sys.stderr,
            )
            return 1
        try:
            browser_process = launch_browser(args)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        browser_info = wait_for_browser_endpoint(
            args.browser_host,
            args.browser_port,
            timeout=args.timeout,
        )

    client: CDPClient | None = None
    recorder: CaptureRecorder | None = None
    banner_printed = False
    created_initial_target = False
    shutdown_reason: str | None = None

    try:
        while True:
            try:
                websocket_url = get_browser_websocket_url(browser_info)
                client = CDPClient(websocket_url, timeout=args.timeout)
                if recorder is None:
                    recorder = CaptureRecorder(
                        client,
                        output_path,
                        quiet=args.quiet,
                        network_enable_params=network_enable_params,
                    )
                else:
                    recorder.bind_client(client)

                configure_capture_client(client, recorder)

                if not created_initial_target:
                    target_id = create_initial_target(client)
                    session_id = wait_for_session_for_target(
                        recorder,
                        client,
                        target_id,
                        timeout=args.timeout,
                    )
                    if args.url != DEFAULT_URL:
                        client.call("Page.navigate", {"url": args.url}, session_id=session_id)
                    created_initial_target = True

                if not banner_printed and not args.quiet:
                    print(f"[cdp] writing capture to {output_path}")
                    print("[cdp] browse in the attached Chrome window(s), then press Ctrl+C to stop")
                    banner_printed = True
                elif banner_printed and not args.quiet:
                    print("[cdp] reconnected to the browser WebSocket")

                drain_events_forever(
                    recorder,
                    client,
                    stalled_after_seconds=args.stalled_after,
                )
            except (EOFError, ConnectionError, OSError) as exc:
                if not args.quiet:
                    print(f"\n[cdp] browser connection lost: {exc}")
                if recorder is not None:
                    recorder.handle_browser_disconnect(
                        "Browser CDP WebSocket disconnected before request completed"
                    )
                if client is not None:
                    with contextlib.suppress(Exception):
                        client.close()
                    client = None
                browser_info = wait_for_browser_endpoint_after_disconnect(
                    args.browser_host,
                    args.browser_port,
                    poll_interval=DEFAULT_RECONNECT_INTERVAL,
                    quiet=args.quiet,
                    browser_process=browser_process,
                )
                continue
    except KeyboardInterrupt:
        shutdown_reason = "Capture stopped before request completed"
        if not args.quiet:
            print("\n[cdp] stopping capture")
    except RuntimeError as exc:
        shutdown_reason = str(exc)
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if recorder is not None:
            if shutdown_reason is not None:
                recorder.print_inflight_requests(reason=shutdown_reason)
            with contextlib.suppress(Exception):
                recorder.close(failure_reason=shutdown_reason)
        if client is not None:
            with contextlib.suppress(Exception):
                client.close()
        if browser_process is not None:
            with contextlib.suppress(Exception):
                browser_process.process.terminate()
            if args.user_data_dir is None and browser_process.user_data_dir:
                with contextlib.suppress(Exception):
                    shutil.rmtree(browser_process.user_data_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(parse_args()))
