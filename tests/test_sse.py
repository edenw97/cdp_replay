import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cdp_replay.capture import parse_sse_events


class ParseSseEventsTest(unittest.TestCase):
    def test_named_and_unnamed_events(self):
        stream = (
            'event: delta_encoding\n'
            'data: "v1"\n'
            '\n'
            'data: {"p":"","o":"add","v":{"message":{"role":"system"}}}\n'
            '\n'
            'event: delta\n'
            'data: {"v":{"message":{"role":"assistant","content":"hi"}}}\n'
            '\n'
            'data: [DONE]\n'
            '\n'
        )
        events = parse_sse_events(stream)
        self.assertEqual(
            [event["event"] for event in events],
            ["delta_encoding", "message", "delta", "message"],
        )
        self.assertEqual(events[0]["data"], '"v1"')
        self.assertEqual(events[3]["data"], "[DONE]")

    def test_multiline_data_and_comments(self):
        stream = (
            ': keep-alive\n'
            'event: answer-text\n'
            'id: 42\n'
            'data: line one\n'
            'data: line two\n'
            '\n'
        )
        events = parse_sse_events(stream)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "answer-text")
        self.assertEqual(events[0]["id"], "42")
        self.assertEqual(events[0]["data"], "line one\nline two")

    def test_crlf_and_trailing_event(self):
        stream = 'data: a\r\n\r\ndata: b\r\n'
        events = parse_sse_events(stream)
        self.assertEqual([event["data"] for event in events], ["a", "b"])

    def test_empty_stream(self):
        self.assertEqual(parse_sse_events(""), [])


if __name__ == "__main__":
    unittest.main()
