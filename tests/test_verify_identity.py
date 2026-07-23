"""verify surfaces the envelope's GitHub identity in four honest states — and never hits
the network for a legacy envelope. The live verify path is monkeypatched so these stay
offline; the real GitHub round-trip is covered by test_identity/test_envelope_identity."""
from scpe import cli
from scpe.envelope import PROTOCOL_VERSION, Envelope, Manifest
from scpe.identity import Identity, IdentityError


def _env(*, sig_method: str = "ssh-github", login: str = "bob") -> Envelope:
    m = Manifest(PROTOCOL_VERSION, "https://github.com/o/r", "0" * 40, "", "Bob", "e@x", "t",
                 github_login=login, sig_method=sig_method)
    return Envelope(manifest=m, briefing_md="", pieces=[], provenance={})


def test_identity_status_verified(monkeypatch):
    monkeypatch.setattr(cli, "verify_envelope_identity",
                        lambda env, **k: Identity(login="bob", pubkey="ssh-ed25519 AAAA"))
    ids = cli._identity_status(_env())
    assert ids["status"] == "verified"
    assert ids["login"] == "bob"
    assert ids["profile"] == "https://github.com/bob"


def test_identity_status_failed_is_a_red_flag(monkeypatch):
    monkeypatch.setattr(cli, "verify_envelope_identity", lambda env, **k: None)
    ids = cli._identity_status(_env())
    assert ids["status"] == "failed"
    assert ids["login"] == "bob"  # the CLAIMED login, surfaced so the owner sees the spoof


def test_identity_status_unchecked_on_network_error(monkeypatch):
    def boom(env, **k):
        raise IdentityError("no network")
    monkeypatch.setattr(cli, "verify_envelope_identity", boom)
    ids = cli._identity_status(_env())
    assert ids["status"] == "unchecked"


def test_identity_status_legacy_does_not_touch_network():
    # sig_method != "ssh-github" -> classified as legacy WITHOUT calling verify at all.
    called = []
    ids = cli._identity_status(_env(sig_method=""))
    assert ids["status"] == "legacy"
    assert called == []  # (no monkeypatch set; legacy path must never invoke verify)
