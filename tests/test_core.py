
from passwordforge.core import check_password_strength, policy_check, password_fingerprint


def test_strength_basic():
    r = check_password_strength("CorrectHorseBatteryStaple!2025")
    assert r["score"] >= 6
    assert r["entropy_bits"] > 40


def test_policy_blocks_common():
    r = policy_check("password", preset="nist")
    assert r["passed"] is False
    assert any(i["code"] == "blocklist.common_password" for i in r["issues"])


def test_fingerprint_stable():
    token1 = password_fingerprint("MySecretPass!123", "secret-key")
    token2 = password_fingerprint("MySecretPass!123", "secret-key")
    assert token1 == token2
