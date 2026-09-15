#!/usr/bin/env python3
"""Command-line dispatcher for the cdp-replay project."""

from __future__ import annotations

import argparse
import sys

from . import capture, client, replay, server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cdp-replay",
        description=(
            "Capture Chrome HTTP traffic via the Chrome DevTools Protocol and "
            "replay the recorded requests against the built-in replay server or "
            "any other endpoint."
        ),
    )
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="{capture,server,client,replay}",
        required=True,
    )

    capture_parser = subparsers.add_parser(
        "capture",
        help="capture HTTP traffic from Chrome via CDP",
        description=capture.DESCRIPTION,
    )
    capture.add_arguments(capture_parser)

    server_parser = subparsers.add_parser(
        "server",
        help="serve recorded HTTP responses from a capture file",
        description=server.DESCRIPTION,
    )
    server.add_arguments(server_parser)

    client_parser = subparsers.add_parser(
        "client",
        help="replay recorded HTTP requests against a base URL",
        description=client.DESCRIPTION,
    )
    client.add_arguments(client_parser)

    replay_parser = subparsers.add_parser(
        "replay",
        help="one-shot replay: embedded server + client, pass/fail exit code",
        description=replay.DESCRIPTION,
    )
    replay.add_arguments(replay_parser)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "capture":
        return capture.main(args)
    if args.command == "server":
        return server.main(args)
    if args.command == "client":
        return client.main(args)
    if args.command == "replay":
        return replay.main(args)
    raise AssertionError(f"unhandled command {args.command!r}")


if __name__ == "__main__":
    sys.exit(main())
