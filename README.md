# cdp-replay

Record real browser HTTP traffic via the Chrome DevTools Protocol (CDP), then replay it:
serve the recorded responses from a mock server, or re-send the recorded requests against
any endpoint.

The project consists of three commands:

| Command   | Purpose                                                          |
|-----------|------------------------------------------------------------------|
| `capture` | Record request/response headers + bodies from Chrome into JSONL |
| `server`  | Serve the recorded responses (mock origin)                      |
| `client`  | Re-send the recorded requests against a base URL                |
| `replay`  | One-shot: embedded server + client, pass/fail exit code         |

A typical round trip:

```
Chrome ──capture──> capture.jsonl ──client──> target endpoint
                          │
                          └──server──> mock origin answering from the file
```

## Requirements

- Python >= 3.10
- `h2` (installed automatically with the package; needed for HTTP/2 replay and serving)
- Chrome or Chromium (for `capture`)

## Usage

Run from the project directory without installing:

```console
$ python -m cdp_replay --help
```

Or install it to get the `cdp-replay` console command:

```console
$ pip install .
$ cdp-replay --help
```

Each command also works standalone, e.g. `python -m cdp_replay.server --help`.

## capture

```console
$ python -m cdp_replay capture --url https://example.com --output session.jsonl
```

Attaches to Chrome (launches a dedicated instance by default, or attaches to an existing
one started with `--remote-debugging-port=9222`) and writes one JSON record per line
containing:

- full request and response headers, including the CDP "extra info" headers
- request and response bodies (base64-encoded when binary)
- status, status text, resource type, timing, initiator, and failure details
- the HTTP protocol used for each request (`http/1.1`, `h2`, `h3`, ...)
- redirect hops (each hop is written as its own record)

Key options:

| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--url URL`                 | initial URL opened after capture starts                    |
| `--output PATH`             | output file (default `cdp_capture_<timestamp>.jsonl`)      |
| `--attach-only`             | never launch a browser, only attach to a running Chrome     |
| `--headless`                | launch the browser headless                                |
| `--browser-host/--browser-port` | remote debugging endpoint (default 127.0.0.1:9222)      |
| `--user-data-dir DIR`       | profile dir for a launched browser (default: temporary)    |
| `--max-resource-buffer-size`, `--max-post-data-size`, `--max-total-buffer-size` | CDP Network.enable buffer limits |
| `--stalled-after SECONDS`  | warn about requests stuck longer than this (0 disables)     |
| `--quiet`                   | suppress live per-request summaries                        |

Notes:

- All page targets are auto-attached, so multi-tab browsing is captured.
- If the browser restarts or the WebSocket drops, the tool flushes in-flight records as
  incomplete and reconnects automatically.
- Press Ctrl+C to stop; pending requests are flushed and reported.
- Records where the body could not be retrieved contain a `body_error` field instead.

## server

```console
$ python -m cdp_replay server session.jsonl --port 8080
```

Serves the recorded responses. Incoming requests are matched to capture entries using a
fallback chain, from most to least specific:

1. method + full original URL + request body hash
2. method + full original URL
3. method + path/query + request body hash
4. method + path/query

Each recorded entry is served at most once, in capture order, so replaying a sequence of
calls to the same URL works naturally. The client normally sends the original URL in the
`X-Replay-Original-URL` header, which enables the two URL-based strategies.

Responses carry `X-Replay-Match` (which strategy matched), `X-Replay-Record-Index`, and
`X-Replay-Original-URL` for debugging. Unmatched requests get a 404 with a JSON
diagnostic. Hop-by-hop headers and `Content-Length` are rewritten; the server forces
`Connection: close`.

Options: `--host` (default `127.0.0.1`), `--port` (default `8080`), `--tls-cert`/`--tls-key`
(serve HTTPS with ALPN advertising both `h2` and `http/1.1`), `--quiet`.

- Without `--tls-cert` the listener is plain HTTP/1.1 only (no h2c).
- With `--tls-cert`/`--tls-key` the listener serves HTTP/1.1 and HTTP/2 on the same
  port: the client picks via ALPN, exactly like a browser. Use a self-signed
  certificate together with the client's `--insecure`.

Recorded HTTP/2 pseudo-headers and CDP multi-line header values (e.g. joined
`set-cookie` lines) are normalized automatically: pseudo-headers are stripped for
HTTP/1.1 replay and re-derived from the request line for H2, and multi-line values
are split into separate header fields.

304/204 responses are replayed bodyless. CDP attaches the *cached* resource body
to a 304, but a 304 never carries a body on the wire, so the recording's body is
dropped and the replayed response is exactly what the origin sent.

## client

```console
$ python -m cdp_replay client session.jsonl --base-url http://127.0.0.1:8080 --verify-body
```

Re-sends every recorded request, rewritten to `--base-url` while keeping the original
path and query. Each request is tagged with `X-Replay-Original-URL`,
`X-Replay-Record-Index`, and `X-Replay-Request-Id` headers.

| Option                       | Description                                              |
|------------------------------|----------------------------------------------------------|
| `--base-url URL`             | target base URL (default `http://127.0.0.1:8080`)        |
| `--proxy HOST:PORT`          | route all requests through an explicit HTTP proxy (absolute-form for `http://`, CONNECT tunnel for `https://`) |
| `--verify-body`              | compare response body SHA256 against the recording      |
| `--stop-on-error`            | abort on the first failure                               |
| `--host-filter`, `--url-filter`, `--method-filter`, `--resource-type-filter` | comma-separated lists restricting what gets replayed |
| `--limit N`                  | replay at most N requests                                |
| `--pace-factor F`            | scale recorded inter-request delays (0 = none, 1 = original timing) |
| `--timeout SECONDS`          | per-request timeout (default 15)                         |
| `--preserve-host`            | send the original Host header                            |
| `--insecure`                 | disable TLS certificate verification for https targets   |
| `--protocol {auto,h1,h2}`    | HTTP version for replay (default `auto`, see below)      |
| `--http2`                    | shortcut for `--protocol h2` (requires an https target)   |

The client picks the protocol per request from the URL scheme and the recorded
protocol (`Network.Response.protocol` is captured per request):

- `auto` (the default) replays https requests with their recorded HTTP version:
  HTTP/2 over TLS with ALPN `h2`, or HTTP/1.1 over TLS. Records captured over
  HTTP/3 are replayed over HTTP/2 with a note.
- Plain `http://` targets always use HTTP/1.1, like a browser: HTTP/2 is never
  spoken in the clear (no h2c). Records captured over H2/H3 are downgraded with
  a printed note.
- `--protocol h2` (or `--http2`) forces HTTP/2 for all requests and errors out
  if the target is not https; `--protocol h1` forces HTTP/1.1.

For HTTP/2 requests:

- `https://` targets use TLS with ALPN `h2` (an error is raised if the target does
  not negotiate h2).
- With `--proxy`, https requests are tunneled: the client sends `CONNECT` to the
  proxy and speaks H2 inside the tunnel over TLS, so the proxy sees realistic
  CONNECT traffic. Plain http requests through a proxy use absolute-form
  HTTP/1.1, exactly like a browser.
- Connections are pooled per origin and reused across requests (sequential streams,
  no multiplexing). `--preserve-host` sets the `:authority` pseudo-header to the
  original recorded host.

Exit status is non-zero if any request mismatched, failed, or (with `--verify-body`) had a
different body — suitable for golden-file regression checks in CI.

HTTPS with a self-signed certificate: use an `https://` base URL together with
`--insecure`.

## replay

One-shot convenience command: start the replay server in-process, replay every
recorded request against it via the client, and exit `0` on pass / `1` on fail.

```console
$ python -m cdp_replay replay session.jsonl
```

On top of the embedded server options, every `client` flag is accepted
(`--proxy`, `--insecure`, `--host-filter`, `--limit`, `--pace-factor`, ...), with two
different defaults:

| Option                        | Description                                              |
|-------------------------------|----------------------------------------------------------|
| `--host`                      | address the embedded server binds to (default `127.0.0.1`, or `0.0.0.0` when `--proxy` points at a remote host) |
| `--port`                      | server port (default `8080`, `0` picks a free port)      |
| `--tls-cert` / `--tls-key`    | run the embedded server with TLS (ALPN h2/http1.1) so HTTP/2 records are replayed over H2; the client is automatically run with `--insecure` for the self-signed case |
| `--base-url URL`              | client target (default: derived from `--host`/`--port`)  |
| `--verify-body` / `--no-verify-body` | response body check (on by default for `replay`)  |

Without `--tls-cert` the embedded server is plain HTTP/1.1, so every record
(including H2/H3 captures) is replayed over HTTP/1.1 with a printed note. Pass
`--tls-cert`/`--tls-key` to exercise HTTP/2.

Without `--proxy`, traffic goes directly from the client to the embedded server. With
`--proxy`, the client's requests are routed through the proxy before they reach the
server, so the device under test sees the full replay:

```console
$ python -m cdp_replay replay session.jsonl --proxy 10.0.0.1:8080
```

Since the server returns byte-exact recorded responses, a PASS through a proxy means the
path delivered every response unmodified; a FAIL pinpoints the first tampered or failed
request.

The server must listen on an address the proxy can reach back to:

- Local proxy (`--proxy 127.0.0.1:...`): the default loopback bind works as-is.
- Remote proxy: the proxy cannot reach your loopback interface. When `--proxy` points at
  a non-local host and `--host` is not given, `replay` binds the server to `0.0.0.0` and
  derives the base URL from the local address that routes towards the proxy, so the proxy
  can connect back.
- Forcing `--host 127.0.0.1` with a remote proxy prints a warning; use the automatic
  binding or pass a routable `--host`/`--base-url` (needed when NAT or asymmetric routing
  means the route-towards-proxy address differs from the address the proxy should use).

## Replay topologies

### Direct (no proxy)

```
client ───────────────────────────> server
```

Point the client straight at the mock origin:

```console
$ python -m cdp_replay client session.jsonl \
    --base-url http://127.0.0.1:8080 --verify-body
```

### Transparent / intercepting proxy

```
client ──> proxy (transparent) ──> server
```

No special client options are needed: redirect traffic to the mock origin through the
proxy as usual (iptables/WCCP/policy routing) and replay exactly as in the direct case.
Add `--preserve-host` so the proxy sees the original recorded host names instead of the
mock origin's address — important when its policy matches on URL/Host.

### Explicit proxy

```
client ──> proxy (--proxy) ──> server
```

Pass the proxy's address with `--proxy host:port`:

```console
$ python -m cdp_replay client session.jsonl \
    --base-url http://127.0.0.1:8080 \
    --proxy 10.0.0.1:8080 --verify-body
```

(or the one-shot equivalent: `python -m cdp_replay replay session.jsonl --proxy 10.0.0.1:8080`)

- `http://` targets: requests are sent to the proxy in absolute-form
  (`GET http://127.0.0.1:8080/path HTTP/1.1`) and the `Host` header names the origin, so
  the proxy can route and match policy exactly as a browser would.
- `https://` targets: the client asks the proxy to `CONNECT`, then sends the request
  inside the tunnel; TLS stays end-to-end with the origin. Combine with `--insecure`
  for self-signed origins.
- Note: `--preserve-host` through an explicit proxy sends a `Host` header naming the
  original recorded host while the absolute URI names the base URL; strict proxies that
  enforce Host/URI consistency may reject that combination.

## Typical workflows

Golden-file regression test (one command after capture):

```console
$ python -m cdp_replay capture --url https://app.example.com --output golden.jsonl
$ python -m cdp_replay replay golden.jsonl
```

Or step by step with `server` + `client`, e.g. when the server must keep running or the
client needs special handling:

```console
$ python -m cdp_replay server golden.jsonl --port 8080 &
$ python -m cdp_replay client golden.jsonl --base-url http://127.0.0.1:8080 --verify-body
```

Mock backend for development: run `server` against a capture of a real session and point
your application at `http://127.0.0.1:8080`.

Middlebox / appliance testing: run `server` as the origin, then replay with `client`
through the device under test (or point a browser at the device with the mock origin
behind it) to see how it handles realistic traffic.

## Limitations

- Replay respects scheme and recorded protocol: https targets use the recorded
  HTTP version (H2 over TLS/ALPN, HTTP/1.1 otherwise; `auto` default, or force
  with `--protocol`). HTTP/3 replay is not supported yet — records captured over
  HTTP/3 are replayed over HTTP/2. Plain http targets always use HTTP/1.1 (no h2c).
- The capture does not record H2 connection/stream grouping, so H2 replay cannot
  reproduce multiplexing: requests are sent sequentially over one reused connection
  per origin.
- Streaming (SSE) response bodies are captured as one accumulated body and replayed as a
  single buffered response; token-by-token streaming behavior is not reproduced.
- WebSocket frames are not captured or replayed.
- Responses depend only on the recording; there is no dynamic state.
- Capture files contain live cookies and bearer tokens in plaintext. Treat them as
  secrets and do not commit them to a shared repository.

## Project layout

```
cdp-replay/
├── pyproject.toml          # package metadata + cdp-replay console script
└── cdp_replay/
    ├── __init__.py
    ├── __main__.py         # subcommand dispatcher (python -m cdp_replay)
    ├── capture.py          # CDP capture command
    ├── common.py           # shared record model, header sanitation, helpers
    ├── server.py           # replay server command
    ├── client.py           # replay client command (HTTP/1.1 + HTTP/2)
    ├── replay.py           # one-shot replay command (embedded server + client)
    └── tests/test_h2.py    # HTTP/2 round-trip tests (unittest)
```
