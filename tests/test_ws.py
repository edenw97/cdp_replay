import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cdp_replay.capture import CaptureRecorder
from cdp_replay.common import load_replay_records


class StubClient:
    """CaptureRecorder only calls the client for HTTP bodies."""

    def call(self, *args, **kwargs):  # pragma: no cover - not used for WS
        raise AssertionError("unexpected CDP call")


def make_recorder(path):
    return CaptureRecorder(
        StubClient(),
        path,
        quiet=True,
        network_enable_params={},
    )


def send(recorder, method, params):
    recorder.handle_event({"method": method, "params": params, "sessionId": "S1"})


class WebSocketCaptureTest(unittest.TestCase):
    def test_websocket_record_with_frames(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            recorder = make_recorder(path)

            send(
                recorder,
                "Network.webSocketCreated",
                {"requestId": "1.1", "url": "wss://ws.example/p0/ws/user/u1"},
            )
            send(
                recorder,
                "Network.webSocketWillSendHandshakeRequest",
                {
                    "requestId": "1.1",
                    "timestamp": 1.0,
                    "wallTime": 1792620000.0,
                    "request": {"headers": {"Upgrade": "websocket"}},
                },
            )
            send(
                recorder,
                "Network.webSocketHandshakeResponseReceived",
                {
                    "requestId": "1.1",
                    "timestamp": 1.1,
                    "response": {
                        "status": 101,
                        "statusText": "Switching Protocols",
                        "headers": {"Upgrade": "websocket"},
                    },
                },
            )
            send(
                recorder,
                "Network.webSocketFrameSent",
                {
                    "requestId": "1.1",
                    "timestamp": 2.0,
                    "response": {
                        "opcode": 1,
                        "payloadData": '{"subscribe":"conversation-turn-abc"}',
                    },
                },
            )
            send(
                recorder,
                "Network.webSocketFrameReceived",
                {
                    "requestId": "1.1",
                    "timestamp": 2.1,
                    "response": {
                        "opcode": 1,
                        "payloadData": '{"type":"answer-text","text":"hi"}',
                    },
                },
            )
            send(recorder, "Network.webSocketClosed", {"requestId": "1.1", "timestamp": 3.0})
            recorder.close()

            with open(path, encoding="utf-8") as handle:
                records = [json.loads(line) for line in handle if line.strip()]

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["resource_type"], "WebSocket")
        self.assertEqual(record["request"]["url"], "wss://ws.example/p0/ws/user/u1")
        self.assertEqual(record["request"]["method"], "GET")
        self.assertEqual(record["response"]["status"], 101)
        websocket = record["websocket"]
        self.assertEqual(websocket["frame_counts"], {"sent": 1, "received": 1})
        self.assertEqual(websocket["frames"][0]["direction"], "sent")
        self.assertIn("conversation-turn-abc", websocket["frames"][0]["payload_data"])
        self.assertEqual(websocket["frames"][1]["direction"], "received")
        self.assertEqual(websocket["frames"][1]["opcode_name"], "text")
        self.assertIsNotNone(websocket["closed"])

    def test_websocket_flushed_as_incomplete_on_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            recorder = make_recorder(path)
            send(recorder, "Network.webSocketCreated", {"requestId": "9", "url": "wss://x/y"})
            recorder.close(failure_reason="capture stopped")

            with open(path, encoding="utf-8") as handle:
                record = json.loads(handle.readline())

        self.assertTrue(record["incomplete"])
        self.assertEqual(record["failure"]["errorText"], "capture stopped")
        self.assertEqual(record["resource_type"], "WebSocket")

    def test_websocket_records_are_skipped_by_replay_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            recorder = make_recorder(path)
            send(recorder, "Network.webSocketCreated", {"requestId": "1", "url": "wss://x/y"})
            recorder.close()

            records, skipped = load_replay_records(path)

        self.assertEqual(records, [])
        self.assertEqual(skipped, 1)


if __name__ == "__main__":
    unittest.main()
