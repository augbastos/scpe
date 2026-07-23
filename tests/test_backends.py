import asyncio, json, threading, http.server
import pytest
from scpe.backends import (
    MockBackend, OpenAICompatBackend, BackendConfigError, make_backend, extract_tag,
)

def test_extract_tag():
    assert extract_tag("[SCPE:ANALYZE]\nrest") == "ANALYZE"
    assert extract_tag("no marker") == ""

def test_mock_dispatches_on_tag():
    b = MockBackend({"ANALYZE": '{"issues": []}'})
    out = asyncio.run(b.complete("sys", "[SCPE:ANALYZE]\nlook at this"))
    assert out == '{"issues": []}'
    assert b.label == "mock"

def test_mock_unknown_tag_returns_stub_json():
    out = asyncio.run(MockBackend().complete("sys", "[SCPE:WHAT]\nx"))
    assert json.loads(out) == {"mock": True, "tag": "WHAT"}

def test_openai_compat_requires_config(monkeypatch):
    for var in ("SCPE_BASE_URL", "SCPE_MODEL", "SCPE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(BackendConfigError):
        OpenAICompatBackend()

class _FakeAPI(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body["model"] == "test-model"
        reply = {"choices": [{"message": {"content": "hello from fake"}}]}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a): pass

def test_openai_compat_round_trip(monkeypatch):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _FakeAPI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        b = OpenAICompatBackend(
            base_url=f"http://127.0.0.1:{srv.server_port}/v1",
            model="test-model", api_key="k")
        out = asyncio.run(b.complete("sys", "[SCPE:PING]\nhi"))
        assert out == "hello from fake"
        assert b.label == "openai-compat:test-model"
    finally:
        srv.shutdown()

def test_make_backend_default_is_mock(monkeypatch):
    monkeypatch.delenv("SCPE_BACKEND", raising=False)
    assert make_backend().label == "mock"
