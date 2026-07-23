"""SSRF invariant coverage for the standalone verifier's key fetch (SPEC.md §8 step 4).

Before this file, `reference/standalone/verify_envelope.py:fetch_keys` / `_NoRedirect`
(verify_envelope.py:216-253) had ZERO direct tests -- the only coverage was indirect,
through the 18 conformance vectors, all of which run offline via `--keys` and so never
touch this code path at all.

SPEC §8 step 4 requires, for the `github` / `gitlab` / `codeberg` providers:
  (a) HTTPS only -- the fetch URL is built as `https://<host>/<subject>.keys`, never http.
  (b) no redirects are ever followed -- a 3xx is a fetch FAILURE, not a hop to take (this
      is the SSRF defense: a redirect is exactly how an attacker/compromised forge could
      bounce the verifier at another host or downgrade the scheme).
  (c) a post-fetch re-check that the resolved URL's scheme/host still match the one
      requested -- belt-and-braces in case anything upstream ever let a redirect slip
      through unnoticed.
  (d) `host` comes ONLY from the fixed `PROVIDER_HOSTS` table (verify_envelope.py:93-98);
      the manifest is attacker-controlled end to end and must not be able to steer it.

Every test here is fully offline: nothing calls a real socket. Two mocking boundaries are
used, matching how this project's other tests mock (test_verify_identity.py monkeypatches
`cli.verify_envelope_identity` directly rather than faking the GitHub API transport):

  1. `urllib.request.build_opener` is monkeypatched to return a fake opener whose `.open()`
     is fully under the test's control -- this exercises the REAL `fetch_keys` URL/TLS
     construction and the REAL post-fetch host re-check, with only the socket layer faked.
  2. `_NoRedirect.redirect_request` (the actual class `fetch_keys` installs into its
     opener) is exercised directly, both in isolation and by having a fake opener invoke it
     the way `urllib`'s real redirect machinery would on a 3xx -- so the exact object that
     ships in production is what raises, not a re-implementation of it in this test.

NOT covered here, by design: a fully faithful simulation of urllib parsing a real 3xx
response off an `http.client.HTTPSConnection` (i.e. mocking one layer deeper, at
`AbstractHTTPHandler.do_open`). That would test urllib's own redirect-dispatch machinery
more than this project's code, and no other test in this suite reaches that deep either.
The two boundaries above are the ones actually worth asserting: does `fetch_keys` install
the no-follow handler and re-check the final URL, and does `_NoRedirect` itself refuse
every redirect it's asked to follow.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from reference.standalone import verify_envelope as ve

ROOT = Path(__file__).resolve().parent.parent
VERIFIER_PY = ROOT / "reference" / "standalone" / "verify_envelope.py"


# --------------------------------------------------------------------------- helpers

def _write_minimal_manifest_dir(tmp_path: Path, manifest: dict) -> Path:
    """A directory shaped like a vector directory (manifest.json + manifest.sig), just
    enough for `verify()` to reach step 4 (key fetch, SPEC §8). `manifest.sig`'s content
    is irrelevant to these tests: the fetch happens BEFORE the signature is ever checked
    (verify_envelope.py:381-398 fetches at step 4, verifies the signature at step 5-6), so
    none of these tests need a validly-signed manifest."""
    d = tmp_path / "vec"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (d / "manifest.sig").write_bytes(b"placeholder -- unreached before the fetch under test\n")
    return d


class _FakeResponse:
    """Stands in for the `http.client.HTTPResponse`-like object `opener.open()` returns,
    supporting exactly what `fetch_keys` uses: the `with ... as resp:` protocol,
    `.geturl()`, and `.read(n)`."""

    def __init__(self, url: str, body: bytes = b"ssh-ed25519 AAAAFAKEKEY test@example\n"):
        self._url = url
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def geturl(self) -> str:
        return self._url

    def read(self, n: int = -1) -> bytes:
        return self._body


# ----------------------------------------------------------- (a) HTTPS only, fixed host

def test_fetch_keys_builds_https_url_from_fixed_host_table(monkeypatch):
    """The URL `fetch_keys` asks its opener to open is ALWAYS `https://<host>/<subject>.keys`
    for a real host, for every forge provider in the fixed table -- never any other scheme,
    and `host` is exactly the value handed in (which callers only ever source from
    PROVIDER_HOSTS, proven separately below)."""
    captured: dict = {}

    class _FakeOpener:
        def open(self, req, timeout=10):
            captured["url"] = req.full_url
            captured["timeout"] = timeout
            return _FakeResponse(req.full_url)

    def fake_build_opener(*handlers):
        captured["handlers"] = handlers
        return _FakeOpener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)

    for provider, host in ve.PROVIDER_HOSTS.items():
        if host is None:
            continue  # `local` never fetches at all (SPEC §8 step 4) -- nothing to assert
        ve.fetch_keys(host, "octocat")
        assert captured["url"] == f"https://{host}/octocat.keys", (provider, captured["url"])
        assert captured["url"].startswith("https://")
        assert "http://" not in captured["url"]
        # the no-follow handler is installed on every fetch, not just some
        assert any(isinstance(h, ve._NoRedirect) for h in captured["handlers"])


def test_verifier_source_has_no_http_scheme_construction():
    """Static defense in depth: the file must never construct a plain-http:// URL anywhere,
    not just for the three hosts exercised above at runtime."""
    src = VERIFIER_PY.read_text(encoding="utf-8")
    assert "http://" not in src


def test_fetch_keys_uses_a_verified_tls_context(monkeypatch):
    """`ssl.create_default_context()` is used un-weakened: hostname checking and
    certificate verification stay ON (verify_envelope.py:243-245)."""
    captured: dict = {}
    real_create_default_context = ssl.create_default_context

    def capturing(*a, **kw):
        ctx = real_create_default_context(*a, **kw)
        captured["ctx"] = ctx
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", capturing)

    class _FakeOpener:
        def open(self, req, timeout=10):
            return _FakeResponse(req.full_url)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: _FakeOpener())

    ve.fetch_keys("github.com", "octocat")

    assert captured["ctx"].check_hostname is True
    assert captured["ctx"].verify_mode == ssl.CERT_REQUIRED


# ------------------------------------------------------------ (b) redirects are refused

def test_no_redirect_handler_refuses_every_redirect_status():
    """Direct unit test of the EXACT class `fetch_keys` installs (`_NoRedirect`,
    verify_envelope.py:218-228): for every 3xx redirect status, `redirect_request` raises
    instead of returning a `Request` aimed at the new (attacker) URL. Returning a Request
    is how a `urllib.request.HTTPRedirectHandler` normally says "follow this" -- raising
    means urllib's opener never issues the second request at all."""
    handler = ve._NoRedirect()
    req = urllib.request.Request("https://github.com/octocat.keys")
    for code in (301, 302, 303, 307, 308):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            handler.redirect_request(
                req, None, code, "redirected", {}, "https://attacker.example/pwned.keys")
        assert "refused" in exc_info.value.reason.lower()
        assert "attacker.example" in exc_info.value.reason  # named in the error, not followed to


class _RedirectingOpener:
    """Simulates what `urllib`'s real `OpenerDirector.open()` does on a 3xx response: it
    hands the redirect off to the installed `HTTPRedirectHandler.redirect_request()`. The
    REAL `_NoRedirect` instance that `fetch_keys` built is used here unmodified -- only the
    underlying socket/transport is faked, the same boundary this project already mocks at
    (test_verify_identity.py monkeypatches `cli.verify_envelope_identity`, not the network)."""

    def __init__(self, no_redirect_handler: "ve._NoRedirect"):
        self._handler = no_redirect_handler

    def open(self, req, timeout=10):
        return self._handler.redirect_request(
            req, None, 302, "Found", {}, "https://attacker.example/pwned.keys")


def _install_redirecting_opener(monkeypatch) -> None:
    def fake_build_opener(*handlers):
        no_redirect = next(h for h in handlers if isinstance(h, ve._NoRedirect))
        return _RedirectingOpener(no_redirect)
    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)


def test_fetch_keys_raises_rather_than_follow_a_redirect(monkeypatch):
    """End to end through `fetch_keys` (not just the handler in isolation): when the
    opener it built encounters a redirect, `fetch_keys` raises an OSError -- it never
    returns bytes read from the attacker's response."""
    _install_redirecting_opener(monkeypatch)
    with pytest.raises(OSError) as exc_info:
        ve.fetch_keys("github.com", "octocat")
    # the exception IS the refusal (SSRF-safe fetch message from `_NoRedirect`), never a
    # response body read from the attacker's URL
    assert "refused" in str(exc_info.value).lower()


def test_verify_surfaces_a_refused_redirect_as_identity_unverifiable_never_verified(
        tmp_path, monkeypatch):
    """Full `verify()` path (SPEC §8 step 4's caller, verify_envelope.py:389-392): a
    refused redirect must land on `identity-unverifiable`, and specifically never on
    `verified` -- the fetch error is caught and turned into a status, not swallowed."""
    manifest = {
        "spec_version": "scpe/0.1",
        "contributor": {"identity": {"provider": "github", "subject": "octocat"}},
    }
    d = _write_minimal_manifest_dir(tmp_path, manifest)
    _install_redirecting_opener(monkeypatch)

    result = ve.verify(d, None, None)

    assert result.status == "identity-unverifiable", (result.status, result.detail)
    assert result.status != "verified"


# --------------------------------------------------------- (c) post-fetch host re-check

def test_fetch_keys_rejects_a_response_whose_final_host_differs(monkeypatch):
    """Defense in depth beyond the no-redirect handler: even if the opener's `.open()`
    ever returned a response from a different host by some other means, `fetch_keys`
    re-checks `resp.geturl()` and refuses it (verify_envelope.py:250-252)."""
    class _FakeOpener:
        def open(self, req, timeout=10):
            return _FakeResponse("https://attacker.example/octocat.keys")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: _FakeOpener())

    with pytest.raises(OSError, match="unexpected URL"):
        ve.fetch_keys("github.com", "octocat")


def test_fetch_keys_rejects_a_response_with_a_downgraded_scheme(monkeypatch):
    """Same re-check, other half: a response reporting `http://` (scheme downgrade) is
    refused even if the host matches."""
    class _FakeOpener:
        def open(self, req, timeout=10):
            return _FakeResponse("http://github.com/octocat.keys")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: _FakeOpener())

    with pytest.raises(OSError, match="unexpected URL"):
        ve.fetch_keys("github.com", "octocat")


# ------------------------------------------------ (d) host is fixed-table-only, never manifest

@pytest.mark.parametrize("provider,host", [
    ("github", "github.com"),
    ("gitlab", "gitlab.com"),
    ("codeberg", "codeberg.org"),
])
def test_verify_never_lets_the_manifest_inject_a_fetch_host(tmp_path, monkeypatch, provider, host):
    """The manifest is entirely attacker-controlled (SPEC §8 / THREAT_MODEL §5). Stuff
    `contributor.identity` with fields no schema defines -- `host`, `url`, `endpoint`,
    even a cloud-metadata SSRF classic -- and prove `fetch_keys` is STILL called with only
    `(host_from_PROVIDER_HOSTS, subject)`: the extra fields are silently ignored, exactly
    as SPEC §8 step 3 requires ("the manifest never carries a hostname, URL, port, scheme,
    or path")."""
    manifest = {
        "spec_version": "scpe/0.1",
        "contributor": {
            "identity": {
                "provider": provider,
                "subject": "octocat",
                "host": "attacker.example",
                "url": "https://attacker.example/pwned",
                "endpoint": "http://169.254.169.254/latest/meta-data",
            },
        },
    }
    d = _write_minimal_manifest_dir(tmp_path, manifest)

    calls = []

    def fake_fetch_keys(fetch_host, subject):
        calls.append((fetch_host, subject))
        raise OSError("network disabled for this test")

    monkeypatch.setattr(ve, "fetch_keys", fake_fetch_keys)

    result = ve.verify(d, None, None)

    # ONLY the fixed-table host was ever contacted -- never attacker.example, never the
    # metadata-service address, never anything read off the manifest.
    assert calls == [(host, "octocat")], calls
    assert result.status == "identity-unverifiable", (result.status, result.detail)


def test_local_provider_performs_no_fetch_regardless_of_manifest_content(tmp_path, monkeypatch):
    """The strongest form of the SSRF defense (implementing-scpe.md:170-173): `local` never
    calls `fetch_keys` at all, even if the manifest stuffs `identity` with URL-shaped junk."""
    manifest = {
        "spec_version": "scpe/0.1",
        "contributor": {
            "identity": {
                "provider": "local",
                "subject": "octocat",
                "host": "attacker.example",
                "url": "https://attacker.example/pwned",
            },
        },
    }
    d = _write_minimal_manifest_dir(tmp_path, manifest)

    calls = []

    def fetch_keys_must_not_be_called(*a):
        calls.append(a)
        raise AssertionError("fetch_keys must never be called for the local provider")

    monkeypatch.setattr(ve, "fetch_keys", fetch_keys_must_not_be_called)

    result = ve.verify(d, None, None)

    assert calls == []
    assert result.status == "identity-unverifiable", (result.status, result.detail)
    assert "owner-supplied" in result.detail
