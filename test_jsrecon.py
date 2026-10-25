import json

import jsrecon as jr

SAMPLE = """
const base = "https://api.example.com/v1";
fetch("/api/v2/users");
axios.get('/internal/admin/metrics');
const img = "/assets/logo.png";          // should be ignored (static)
const key = "AKIAIOSFODNN7EXAMPLE";
const g = "AIzaSyA1234567890abcdefghijklmnopqrstuv";  // 35 chars after AIza
const token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123456;
password = "supersecretvalue123";
"""


def test_endpoints_found_and_static_ignored():
    eps = {f.value for f in jr.scan_endpoints(SAMPLE, "x.js")}
    assert "https://api.example.com/v1" in eps
    assert "/api/v2/users" in eps
    assert "/internal/admin/metrics" in eps
    assert "/assets/logo.png" not in eps  # static asset filtered out


def test_secrets_detected_and_redacted():
    secs = jr.scan_secrets(SAMPLE, "x.js")
    notes = " ".join(f.note for f in secs)
    assert "AWS access key id" in notes
    assert "Google API key" in notes
    assert "JSON Web Token" in notes
    assert "generic key/secret assignment" in notes
    assert all("AKIAIOSFODNN7EXAMPLE" != f.value for f in secs)
    assert any(f.value.startswith("AKIA") and "***" in f.value for f in secs)


def test_no_false_positive_on_clean_text():
    clean = 'const greeting = "hello world"; const n = 42;'
    assert jr.scan_secrets(clean, "c.js") == []


def test_kind_filter():
    only_secrets = jr.scan_text(SAMPLE, "x.js", "secrets")
    assert only_secrets and all(f.kind == "secret" for f in only_secrets)
    only_eps = jr.scan_text(SAMPLE, "x.js", "endpoints")
    assert only_eps and all(f.kind == "endpoint" for f in only_eps)


def test_json_output_serialisable():
    f = jr.scan_text(SAMPLE, "x.js", "all")
    data = json.loads(jr.render_json(f))
    assert isinstance(data, list) and {"kind", "value", "source", "line", "note"} <= set(data[0])


def test_fail_on_secret_exit_code(tmp_path):
    p = tmp_path / "leak.js"
    p.write_text('const k = "AKIAIOSFODNN7EXAMPLE";')
    assert jr.main([str(p), "--fail-on-secret", "--format", "json"]) == 2
    clean = tmp_path / "ok.js"
    clean.write_text('fetch("/api/ping");')
    assert jr.main([str(clean), "--fail-on-secret", "--format", "json"]) == 0
