
from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .core import (
    DEFAULT_POLICIES,
    password_fingerprint,
    safe_report_payload,
)
from .attest import attest, canonical_json, sha256_hex, verify_ed25519


class CheckRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Password to evaluate. Never stored.")
    hints: List[str] = Field(default_factory=list, description="Optional personal hints to warn about inclusion.")
    mode: str = Field(default="offline", description="offline|online (affects crack-time estimate)")
    policy_preset: str = Field(default="nist", description="nist|strong|basic (or pass custom via policy)")
    policy: Optional[Dict[str, Any]] = Field(default=None, description="Optional custom policy overrides.")
    include_fingerprint: bool = Field(default=True, description="Include privacy-preserving reuse fingerprint (HMAC).")
    include_attestation: bool = Field(default=True, description="Include cryptographic attestation of the report payload.")


class GenerateRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=128)
    safe_symbols: bool = Field(default=True, description="Use safer symbol set (less website issues).")
    no_ambiguous: bool = Field(default=True, description="Avoid ambiguous characters (O0oIl1 etc).")


class PassphraseRequest(BaseModel):
    words: int = Field(default=4, ge=3, le=12)
    separator: str = Field(default="-", min_length=1, max_length=3)
    safe_symbols: bool = Field(default=True)


class SuggestRequest(BaseModel):
    base: str = Field(..., min_length=1, description="Base word/name to mutate into safer passwords.")
    count: int = Field(default=5, ge=1, le=20)
    total_length: int = Field(default=14, ge=10, le=64)
    similarity: float = Field(default=0.55, ge=0.2, le=0.9, description="0.2..0.9 (higher => closer to base)")


class VerifyRequest(BaseModel):
    payload: Dict[str, Any]
    sha256: str
    signature: Optional[str] = None
    public_key_pem: Optional[str] = None


def create_app() -> FastAPI:
    app = FastAPI(
        title="PasswordForge API",
        version=__version__,
        description="Password strength checker + generator + suggestions with privacy-preserving fingerprints and report attestations.",
    )

    # In-memory report store (NO raw passwords stored).
    REPORTS: Dict[str, Dict[str, Any]] = {}

    FINGERPRINT_SECRET = os.getenv("FINGERPRINT_SECRET", "")
    ATTEST_PRIVATE_KEY = os.getenv("ATTEST_ED25519_PRIVATE_KEY_PEM", "")

    @app.get("/")
    def root() -> Dict[str, Any]:
        return {
            "tool": "PasswordForge",
            "version": __version__,
            "endpoints": ["/health", "/check", "/generate", "/passphrase", "/suggest", "/reports/{report_id}", "/attestation/verify"],
            "note": "This API never stores raw passwords. Reports contain optional privacy-preserving fingerprints only.",
        }

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/check")
    def check(req: CheckRequest) -> Dict[str, Any]:
        t0 = time.time()

        # Generate report/policy (no password returned)
        payload = safe_report_payload(req.password, hints=req.hints, preset=req.policy_preset)
        if req.policy:
            # merge overrides
            merged = payload["policy"]["policy"]
            merged.update(req.policy)
            # recompute policy with merged
            from .core import policy_check
            payload["policy"] = policy_check(req.password, policy=merged, preset=None)

        out: Dict[str, Any] = {
            "report": payload["report"],
            "policy": payload["policy"],
        }

        # Optional privacy-preserving fingerprint (HMAC)
        if req.include_fingerprint:
            if not FINGERPRINT_SECRET:
                out["fingerprint"] = {"enabled": False, "reason": "Set FINGERPRINT_SECRET env var to enable."}
            else:
                out["fingerprint"] = {
                    "enabled": True,
                    "token": password_fingerprint(req.password, FINGERPRINT_SECRET),
                    "note": "Same password => same token. Token is non-reversible without the secret.",
                }

        # Attest the output payload (excluding password)
        if req.include_attestation:
            attest_payload = {"report": out["report"], "policy": out["policy"], "fingerprint": out.get("fingerprint")}
            out["attestation"] = attest(attest_payload, private_key_pem=ATTEST_PRIVATE_KEY or None)

        report_id = str(uuid.uuid4())
        REPORTS[report_id] = {"id": report_id, **out}
        out["report_id"] = report_id
        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        return out

    @app.get("/reports/{report_id}")
    def get_report(report_id: str) -> Dict[str, Any]:
        if report_id not in REPORTS:
            raise HTTPException(status_code=404, detail="Report not found")
        return REPORTS[report_id]

    @app.post("/generate")
    def generate(req: GenerateRequest) -> Dict[str, Any]:
        from .core import generate_password, check_password_strength
        pwd = generate_password(length=req.length, safe_symbols=req.safe_symbols, no_ambiguous=req.no_ambiguous)
        return {"password": pwd, "report": check_password_strength(pwd)}

    @app.post("/passphrase")
    def passphrase(req: PassphraseRequest) -> Dict[str, Any]:
        from .core import generate_passphrase, check_password_strength
        p = generate_passphrase(num_words=req.words, separator=req.separator, safe_symbols=req.safe_symbols)
        return {"passphrase": p, "report": check_password_strength(p)}

    @app.post("/suggest")
    def suggest(req: SuggestRequest) -> Dict[str, Any]:
        from .core import generate_similar_passwords, check_password_strength
        pwds = generate_similar_passwords(
            base=req.base,
            count=req.count,
            total_length=req.total_length,
            similarity=req.similarity,
            safe_symbols=True,
            no_ambiguous=True,
        )
        return {"base": req.base, "suggestions": [{"password": p, "report": check_password_strength(p, hints=[req.base])} for p in pwds]}

    @app.post("/attestation/verify")
    def verify(req: VerifyRequest) -> Dict[str, Any]:
        msg = canonical_json(req.payload)
        digest = sha256_hex(msg)
        ok_hash = (digest == req.sha256)
        ok_sig = None
        if req.signature and req.public_key_pem:
            ok_sig = verify_ed25519(req.public_key_pem, msg, req.signature)
        return {"hash_ok": ok_hash, "computed_sha256": digest, "signature_ok": ok_sig}

    @app.get("/policies")
    def policies() -> Dict[str, Any]:
        return {"presets": DEFAULT_POLICIES}

    return app
