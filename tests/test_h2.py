import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cdp_replay import client, server


OPENSSL = shutil.which("openssl")


def make_record(index, method, url, *, req_body="", resp_body="hello", status=200, protocol="h2"):
    return {
        "request_id": f"req-{index}",
        "captured_at": "2026-01-01T00:00:00Z",
        "resource_type": "XHR",
        "request": {
            "method": method,
            "url": url,
            "headers": {
                ":method": method,
                ":authority": "origin.example",
                ":scheme": "https",
                ":path": "/",
                "user-agent": "cdp-replay-test/1.0",
                "accept": "*/*",
            },
            "body": {"text": req_body} if req_body else None,
        },
        "response": {
            "status": status,
            "headers": {"content-type": "text/plain"},
            "protocol": protocol,
            "body": {"text": resp_body},
        },
        "timing": {"wall_time": 1000.0 + index},
    }


def write_capture(records):
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".jsonl", delete=False, encoding="utf-8"
    )
    try:
        for record in records:
            handle.write(json.dumps(record) + "\n")
        handle.close()
        return handle.name
    except BaseException:
        handle.close()
        os.unlink(handle.name)
        raise


class ServerTestBase(unittest.TestCase):
    use_tls = False

    @classmethod
    def setUpClass(cls):
        cls.cert_path = None
        cls.key_path = None
        if cls.use_tls:
            if OPENSSL is None:
                raise unittest.SkipTest("openssl is required for TLS tests")
            cert_dir = tempfile.mkdtemp(prefix="cdp-replay-test-")
            cls.cert_path = os.path.join(cert_dir, "cert.pem")
            cls.key_path = os.path.join(cert_dir, "key.pem")
            subprocess.run(
                [
                    OPENSSL,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    cls.key_path,
                    "-out",
                    cls.cert_path,
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=127.0.0.1",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )

    @classmethod
    def tearDownClass(cls):
        if cls.cert_path and os.path.dirname(cls.cert_path):
            shutil.rmtree(os.path.dirname(cls.cert_path), ignore_errors=True)

    def setUp(self):
        self.records = [
            make_record(0, "GET", "https://origin.example/a?x=1", resp_body="alpha"),
            make_record(1, "POST", "https://origin.example/b", req_body="posted-data", resp_body="beta"),
            make_record(2, "POST", "https://origin.example/b", req_body="other-data", resp_body="beta-2", protocol="http/1.1"),
            make_record(3, "HEAD", "https://origin.example/c", resp_body=""),
            make_record(
                4,
                "GET",
                "https://origin.example/big",
                resp_body="Z" * (512 * 1024),
            ),
            make_record(5, "GET", "https://origin.example/h3only", resp_body="gamma", protocol="h3"),
            make_record(
                6,
                "GET",
                "https://origin.example/cached.svg",
                resp_body="<svg>cached-bytes</svg>",
                status=304,
            ),
        ]
        self.capture_path = write_capture(self.records)
        records, skipped = client.load_replay_records(self.capture_path)
        self.assertEqual(skipped, 0)
        for record, raw in zip(records, self.records):
            self.assertEqual(record.protocol, raw["response"]["protocol"])
        self.assertEqual(records[6].response_status, 304)
        self.assertEqual(records[6].response_body, b"")
        tls_context = None
        if self.use_tls:
            tls_context = server.build_tls_context(self.cert_path, self.key_path)
        self.replay_server = server.ReplayServer(
            ("127.0.0.1", 0),
            server.ReplayRequestHandler,
            matcher=server.ReplayMatcher(records),
            verbose=False,
            tls_context=tls_context,
        )
        threading.Thread(target=self.replay_server.serve_forever, daemon=True).start()
        self.port = int(self.replay_server.server_address[1])
        scheme = "https" if tls_context is not None else "http"
        self.base_url = f"{scheme}://127.0.0.1:{self.port}"
        self.addCleanup(self.replay_server.shutdown)
        self.addCleanup(self.replay_server.server_close)
        self.addCleanup(os.unlink, self.capture_path)

    def client_args(self, **overrides):
        defaults = dict(
            capture=self.capture_path,
            base_url=self.base_url,
            proxy=None,
            host_filter=None,
            url_filter=None,
            method_filter=None,
            resource_type_filter=None,
            limit=None,
            pace_factor=0.0,
            timeout=10.0,
            verify_body=True,
            stop_on_error=False,
            preserve_host=False,
            insecure=self.use_tls,
            http2=False,
            protocol="auto",
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def run_client(self, **overrides):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            rc = client.main(self.client_args(**overrides))
        return rc, output.getvalue()


@unittest.skipIf(OPENSSL is None, "openssl is required for TLS tests")
class H2OverTlsTest(ServerTestBase):
    use_tls = True

    def test_transport_round_trip(self):
        transport = client.H2Transport(timeout=10.0, insecure=True)
        self.addCleanup(transport.close)

        response = transport.request(
            method="GET",
            scheme="https",
            host="127.0.0.1",
            port=self.port,
            authority="origin.example",
            path_query="/a?x=1",
            header_items=[("x-replay-original-url", "https://origin.example/a?x=1")],
            body=b"",
        )
        self.assertEqual(client._h2_status_code(response.headers), 200)
        self.assertEqual(bytes(response.body), b"alpha")

        response = transport.request(
            method="POST",
            scheme="https",
            host="127.0.0.1",
            port=self.port,
            authority="origin.example",
            path_query="/b",
            header_items=[("x-replay-original-url", "https://origin.example/b")],
            body=b"posted-data",
        )
        self.assertEqual(client._h2_status_code(response.headers), 200)
        self.assertEqual(bytes(response.body), b"beta")

        response = transport.request(
            method="GET",
            scheme="https",
            host="127.0.0.1",
            port=self.port,
            authority="origin.example",
            path_query="/nope",
            header_items=[],
            body=b"",
        )
        self.assertEqual(client._h2_status_code(response.headers), 404)

    def test_transport_rejects_plain_http(self):
        transport = client.H2Transport(timeout=10.0, insecure=True)
        self.addCleanup(transport.close)
        with self.assertRaises(client.H2TransportError):
            transport.request(
                method="GET",
                scheme="http",
                host="127.0.0.1",
                port=self.port,
                authority="origin.example",
                path_query="/a?x=1",
                header_items=[],
                body=b"",
            )

    def test_transport_reuses_one_connection(self):
        opened = []

        original_open = client.H2Transport._open

        def tracked_open(inner_self, scheme, host, port):
            opened.append((scheme, host, port))
            return original_open(inner_self, scheme, host, port)

        with unittest.mock.patch.object(client.H2Transport, "_open", tracked_open):
            transport = client.H2Transport(timeout=10.0, insecure=True)
            self.addCleanup(transport.close)
            for _ in range(3):
                transport.request(
                    method="GET",
                    scheme="https",
                    host="127.0.0.1",
                    port=self.port,
                    authority="origin.example",
                    path_query="/a?x=1",
                    header_items=[("x-replay-original-url", "https://origin.example/a?x=1")],
                    body=b"",
                )
        self.assertEqual(len(opened), 1)

    def test_large_response_flow_control(self):
        transport = client.H2Transport(timeout=10.0, insecure=True)
        self.addCleanup(transport.close)
        response = transport.request(
            method="GET",
            scheme="https",
            host="127.0.0.1",
            port=self.port,
            authority="origin.example",
            path_query="/big",
            header_items=[("x-replay-original-url", "https://origin.example/big")],
            body=b"",
        )
        self.assertEqual(client._h2_status_code(response.headers), 200)
        self.assertEqual(len(response.body), 512 * 1024)

    def test_client_main_auto_respects_recorded_protocol(self):
        rc, output = self.run_client()
        self.assertEqual(rc, 0, output)
        self.assertIn("(1 HTTP/1.1, 6 HTTP/2)", output)
        self.assertIn("1 record(s) were captured over HTTP/3", output)

    def test_client_main_http2(self):
        rc, output = self.run_client(http2=True)
        self.assertEqual(rc, 0, output)
        self.assertIn("(0 HTTP/1.1, 7 HTTP/2)", output)

    def test_client_main_force_protocol_h2(self):
        rc, output = self.run_client(protocol="h2")
        self.assertEqual(rc, 0, output)
        self.assertIn("(0 HTTP/1.1, 7 HTTP/2)", output)

    def test_client_main_force_protocol_h1(self):
        rc, output = self.run_client(protocol="h1")
        self.assertEqual(rc, 0, output)
        self.assertIn("(7 HTTP/1.1, 0 HTTP/2)", output)


class PlainHttpProtocolTest(ServerTestBase):
    use_tls = False

    def test_auto_replays_everything_over_http1(self):
        rc, output = self.run_client()
        self.assertEqual(rc, 0, output)
        self.assertIn("(7 HTTP/1.1, 0 HTTP/2)", output)
        self.assertIn(
            "6 record(s) were captured over HTTP/2 or HTTP/3 but replay over HTTP/1.1",
            output,
        )

    def test_force_http2_over_plain_http_is_an_error(self):
        rc, output = self.run_client(http2=True)
        self.assertEqual(rc, 2, output)
        self.assertIn("requires an https target", output)

    def test_force_protocol_h2_over_plain_http_is_an_error(self):
        rc, output = self.run_client(protocol="h2")
        self.assertEqual(rc, 2, output)
        self.assertIn("requires an https target", output)

    def test_force_protocol_h1_over_plain_http(self):
        rc, output = self.run_client(protocol="h1")
        self.assertEqual(rc, 0, output)
        self.assertIn("(7 HTTP/1.1, 0 HTTP/2)", output)


if __name__ == "__main__":
    unittest.main()
