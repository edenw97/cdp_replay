#!/usr/bin/env python3
"""Shared helpers for replaying HTTP traffic captured via the capture command."""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterator


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
}

CLIENT_SUPPRESSED_REQUEST_HEADERS = HOP_BY_HOP_HEADERS | {
    "content-length",
    "host",
}

SERVER_SUPPRESSED_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | {
    "content-length",
    "content-encoding",
    "date",
    "server",
}


@dataclass(frozen=True)
class ReplayRecord:
    index: int
    request_id: str
    captured_at: str
    resource_type: str | None
    method: str
    url: str
    scheme: str
    host: str
    path_query: str
    request_headers: dict[str, str]
    request_body: bytes
    request_body_hash: str
    request_content_type: str | None
    response_status: int | None
    response_reason: str | None
    response_headers: dict[str, str]
    response_body: bytes
    response_body_hash: str
    response_content_type: str | None
    recorded_wall_time: float | None
    failure: dict[str, Any] | None
    raw: dict[str, Any]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merge_header_maps(section: dict[str, Any]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for key in ("headers", "extra_headers"):
        header_map = section.get(key) or {}
        for name, value in header_map.items():
            if isinstance(value, list):
                merged[str(name)] = ", ".join(str(item) for item in value)
            else:
                merged[str(name)] = str(value)
    return merged


def header_lookup(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == target:
            return value
    return None


def parse_charset(content_type: str | None) -> str | None:
    if not content_type:
        return None
    parts = [part.strip() for part in content_type.split(";")]
    for part in parts[1:]:
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        if name.strip().lower() != "charset":
            continue
        return value.strip().strip("\"'")
    return None


def decode_body_blob(blob: dict[str, Any] | None, *, content_type: str | None) -> bytes:
    if not blob:
        return b""

    if blob.get("base64Encoded"):
        base64_value = blob.get("base64")
        if base64_value is None:
            base64_value = blob.get("text", "")
        if not isinstance(base64_value, str):
            return b""
        return base64.b64decode(base64_value)

    text = blob.get("text", "")
    if not isinstance(text, str):
        return b""

    charset = parse_charset(content_type) or "utf-8"
    try:
        return text.encode(charset)
    except UnicodeEncodeError:
        return text.encode("utf-8", errors="replace")
    except LookupError:
        return text.encode("utf-8", errors="replace")


def request_body_bytes(record: dict[str, Any]) -> bytes:
    request = record.get("request") or {}
    headers = merge_header_maps(request)
    return decode_body_blob(
        request.get("body"),
        content_type=header_lookup(headers, "Content-Type"),
    )


def response_body_bytes(record: dict[str, Any]) -> bytes:
    response = record.get("response") or {}
    headers = merge_header_maps(response)
    return decode_body_blob(
        response.get("body"),
        content_type=header_lookup(headers, "Content-Type"),
    )


def build_replay_record(
    index: int,
    raw: dict[str, Any],
    *,
    require_response_status: bool,
) -> ReplayRecord | None:
    request = raw.get("request") or {}
    method = request.get("method")
    url = request.get("url")
    if not isinstance(method, str) or not method:
        return None
    if not isinstance(url, str) or not url:
        return None

    parsed_url = urllib.parse.urlsplit(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        return None

    response = raw.get("response") or {}
    response_status = response.get("status")
    if require_response_status and not isinstance(response_status, int):
        return None

    path = parsed_url.path or "/"
    path_query = urllib.parse.urlunsplit(("", "", path, parsed_url.query, ""))

    merged_request_headers = merge_header_maps(request)
    merged_response_headers = merge_header_maps(response)
    req_body = request_body_bytes(raw)
    resp_body = response_body_bytes(raw)
    timing = raw.get("timing") or {}

    return ReplayRecord(
        index=index,
        request_id=str(raw.get("request_id", "")),
        captured_at=str(raw.get("captured_at", "")),
        resource_type=raw.get("resource_type"),
        method=method.upper(),
        url=url,
        scheme=parsed_url.scheme,
        host=parsed_url.netloc,
        path_query=path_query,
        request_headers=merged_request_headers,
        request_body=req_body,
        request_body_hash=sha256_hex(req_body),
        request_content_type=header_lookup(merged_request_headers, "Content-Type"),
        response_status=response_status if isinstance(response_status, int) else None,
        response_reason=response.get("status_text"),
        response_headers=merged_response_headers,
        response_body=resp_body,
        response_body_hash=sha256_hex(resp_body),
        response_content_type=header_lookup(merged_response_headers, "Content-Type"),
        recorded_wall_time=timing.get("wall_time"),
        failure=raw.get("failure"),
        raw=raw,
    )


def load_replay_records(
    path: str,
    *,
    require_response_status: bool = True,
) -> tuple[list[ReplayRecord], int]:
    records: list[ReplayRecord] = []
    skipped = 0

    with open(path, encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            record = build_replay_record(
                index=index,
                raw=raw,
                require_response_status=require_response_status,
            )
            if record is None:
                skipped += 1
                continue
            records.append(record)

    return records, skipped


def iter_raw_capture(path: str) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def rewrite_url_to_base(original_url: str, base_url: str) -> str:
    original = urllib.parse.urlsplit(original_url)
    base = urllib.parse.urlsplit(base_url)
    if base.scheme not in {"http", "https"} or not base.netloc:
        raise ValueError(f"Base URL must include scheme and host, got {base_url!r}")
    return urllib.parse.urlunsplit(
        (base.scheme, base.netloc, original.path or "/", original.query, "")
    )


def sanitize_request_headers(
    headers: dict[str, str],
    *,
    preserve_host: bool,
    original_host: str,
) -> dict[str, str]:
    clean: dict[str, str] = {}
    for name, value in headers.items():
        lower_name = name.lower()
        if lower_name in CLIENT_SUPPRESSED_REQUEST_HEADERS:
            continue
        clean[name] = value
    if preserve_host:
        clean["Host"] = original_host
    return clean


def sanitize_response_headers(headers: dict[str, str], body: bytes) -> dict[str, str]:
    clean: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SERVER_SUPPRESSED_RESPONSE_HEADERS:
            continue
        clean[name] = value
    clean["Content-Length"] = str(len(body))
    clean["Connection"] = "close"
    return clean
