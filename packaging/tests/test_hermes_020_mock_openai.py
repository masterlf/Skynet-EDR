import http.client
import importlib.util
import json
import threading
import unittest
from pathlib import Path

MODULE = (
    Path(__file__).resolve().parents[1]
    / "spikes"
    / "hermes-020"
    / "mock_openai.py"
)


def load_fixture():
    spec = importlib.util.spec_from_file_location("hermes_020_mock_openai", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Hermes020MockOpenAITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = load_fixture()
        cls.server = cls.fixture.HTTPServer(
            ("127.0.0.1", 0), cls.fixture.FixtureHandler
        )
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, method, path, *, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, payload

    def raw_post_with_length(self, length):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.putrequest("POST", "/v1/chat/completions")
        if length is not None:
            connection.putheader("Content-Length", str(length))
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, payload

    def test_known_model_routes_are_exact(self):
        status, payload = self.request("GET", "/v1/models")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["data"][0]["id"], "spike-model")

        status, payload = self.request("GET", "/v1/models/spike-model")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["id"], "spike-model")

        status, _ = self.request("GET", "/v1/models/not-the-fixture")
        self.assertEqual(status, 404)

    def test_chat_completions_supports_nonstream_and_stream(self):
        request = json.dumps(
            {"model": "spike-model", "messages": [], "stream": False}
        ).encode()
        status, payload = self.request(
            "POST",
            "/v1/chat/completions",
            body=request,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["choices"][0]["message"]["content"], "SPIKE_OK")

        stream_request = json.dumps(
            {"model": "spike-model", "messages": [], "stream": True}
        ).encode()
        status, payload = self.request(
            "POST",
            "/v1/chat/completions",
            body=stream_request,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertIn(b'"content":"SPIKE_OK"', payload)
        self.assertTrue(payload.endswith(b"data: [DONE]\n\n"))

    def test_unknown_post_and_model_fail_closed(self):
        status, _ = self.request("POST", "/unknown", body=b"{}")
        self.assertEqual(status, 404)

        request = json.dumps({"model": "wrong", "stream": False}).encode()
        status, _ = self.request("POST", "/v1/chat/completions", body=request)
        self.assertEqual(status, 400)

    def test_malformed_and_non_object_json_fail_closed(self):
        status, _ = self.request("POST", "/v1/chat/completions", body=b"{")
        self.assertEqual(status, 400)

        status, _ = self.request("POST", "/v1/chat/completions", body=b"[]")
        self.assertEqual(status, 400)

    def test_content_length_is_required_and_bounded(self):
        status, _ = self.raw_post_with_length(None)
        self.assertEqual(status, 411)

        status, _ = self.raw_post_with_length(self.fixture.MAX_REQUEST_BYTES + 1)
        self.assertEqual(status, 413)


if __name__ == "__main__":
    unittest.main()
