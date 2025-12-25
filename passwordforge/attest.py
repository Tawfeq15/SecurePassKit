
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON encoding for hashing/signing.
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def sign_ed25519(private_pem: str, message: bytes) -> str:
    key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key is not Ed25519")
    sig = key.sign(message)
    return b64url_encode(sig)


def verify_ed25519(public_pem: str, message: bytes, signature_b64url: str) -> bool:
    key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key is not Ed25519")
    try:
        key.verify(b64url_decode(signature_b64url), message)
        return True
    except InvalidSignature:
        return False


def attest(payload: Dict[str, Any], private_key_pem: Optional[str] = None) -> Dict[str, Any]:
    """
    Returns:
      {
        "sha256": "...",
        "signed": bool,
        "signature": "..." | None
      }
    """
    msg = canonical_json(payload)
    digest = sha256_hex(msg)
    out: Dict[str, Any] = {"sha256": digest, "signed": False, "signature": None}
    if private_key_pem:
        out["signature"] = sign_ed25519(private_key_pem, msg)
        out["signed"] = True
    return out
