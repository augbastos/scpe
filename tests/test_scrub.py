from scpe.scrub import scrub

def test_scrubs_api_keys_and_tokens():
    s = scrub("key " + "sk-ant-" + "api03-" + "A" * 24 + " and " + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
    assert "sk-ant" not in s and "ghp_" not in s and "[REDACTED]" in s

def test_scrubs_assignments_and_bearer():
    s = scrub('password="hunter2" Authorization: Bearer abc.def.ghi api_key=xyz123')
    assert "hunter2" not in s and "abc.def.ghi" not in s and "xyz123" not in s

def test_scrubs_pem_block():
    s = scrub("-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----")
    assert "MII" not in s and "[REDACTED]" in s

def test_scrubs_stripe_secret_keys():
    for k in ("sk_live_" + "51H8xIaK9mNoPqRsTuVwXyZ12", "sk_test_" + "51H8xIaK9mNoPqRsTuVwXyZ12"):
        s = scrub(f"stripe = {k}")
        assert k not in s and "[REDACTED]" in s

def test_scrubs_google_api_key():
    k = "AIza" + ("a1B2c3D4e5" * 4)[:35]  # AIza + exactly 35 key chars
    s = scrub(f"google_key {k}")
    assert k not in s and "[REDACTED]" in s

def test_scrubs_slack_token():
    k = "xoxb-" + "1234567890-abcdefghijkl"
    s = scrub(f"slack {k}")
    assert k not in s and "[REDACTED]" in s

def test_scrubs_aws_secret_access_key():
    k = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"  # canonical 40-char AWS secret (split to dodge scanners)
    named = scrub(f'aws_secret_access_key = "{k}"')
    bare = scrub(f"the leaked value is {k} here")  # entropy fallback, no name hint
    assert k not in named and k not in bare and "[REDACTED]" in named and "[REDACTED]" in bare

def test_entropy_fallback_spares_lowercase_git_sha():
    """A 40-char all-lowercase-hex commit id must survive (no uppercase → not a secret)."""
    sha = "0123456789abcdef0123456789abcdef01234567"
    assert sha in scrub(f"base_sha {sha}")

def test_plain_text_untouched():
    assert scrub("def add(a, b): return a + b") == "def add(a, b): return a + b"

def test_scrubs_github_token_family():
    for k in ("gho_" + "aB1cD2eF3gH4iJ5kL6mN7o", "ghs_" + "aB1cD2eF3gH4iJ5kL6mN7o",
             "ghr_" + "aB1cD2eF3gH4iJ5kL6mN7o", "ghu_" + "aB1cD2eF3gH4iJ5kL6mN7o"):
        s = scrub(f"token: {k}")
        assert k not in s and "[REDACTED]" in s

def test_scrubs_gitlab_token():
    k = "glpat-" + "aB1cD2eF3gH4iJ5kL6mN7oP8"
    s = scrub(f"gitlab token {k}")
    assert k not in s and "[REDACTED]" in s

def test_scrubs_aws_temp_access_key_id():
    k = "ASIA" + "IOSFODNN7EXAMPLE"
    s = scrub(f"aws temp key {k}")
    assert k not in s and "[REDACTED]" in s

def test_scrubs_slack_app_token():
    k = "xapp-" + "1-A01234ABCD-1234567890-abcdefghij1234567890abcdefghij"
    s = scrub(f"slack app token {k}")
    assert k not in s and "[REDACTED]" in s

def test_scrubs_jwt():
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
          ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
          ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    s = scrub(f"auth header {jwt}")
    assert jwt not in s and "[REDACTED]" in s

def test_scrubs_compound_secret_identifiers():
    """The name-based rule used to require the keyword to START the identifier (`\\b` right
    before `secret`/`token`/`key`/`password`) — `client_secret`, `db_password`, and
    `session_secret_key` all have a prefix, so none of them used to match."""
    for text, needle in (
        ('client_secret = "abcd1234"', "abcd1234"),
        ('db_password="hunter22"', "hunter22"),
        ('session_secret_key = "zzzz9999"', "zzzz9999"),
    ):
        s = scrub(text)
        assert needle not in s and "[REDACTED]" in s
