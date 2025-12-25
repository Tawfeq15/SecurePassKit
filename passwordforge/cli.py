
from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, List

from .core import (
    check_password_strength,
    generate_password,
    generate_passphrase,
    generate_similar_passwords,
    policy_check,
)
from .api import create_app


def _dump(obj: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    else:
        print(obj)


def main(argv: List[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="passwordforge", description="PasswordForge — check/generate/suggest passwords (safe, defensive).")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Check password strength and policy compliance.")
    p_check.add_argument("password", help="Password to evaluate (not stored).")
    p_check.add_argument("--hint", action="append", default=[], help="Optional hint(s) like name/email/username to flag if included.")
    p_check.add_argument("--mode", choices=["offline", "online"], default="offline")
    p_check.add_argument("--preset", choices=["nist", "strong", "basic"], default="nist")
    p_check.add_argument("--json", action="store_true")

    p_policy = sub.add_parser("policy", help="Run policy-only checks.")
    p_policy.add_argument("password")
    p_policy.add_argument("--preset", choices=["nist", "strong", "basic"], default="nist")
    p_policy.add_argument("--json", action="store_true")

    p_gen = sub.add_parser("gen", help="Generate a strong random password.")
    p_gen.add_argument("--length", type=int, default=16)
    p_gen.add_argument("--safe-symbols", action="store_true", default=True)
    p_gen.add_argument("--allow-ambiguous", action="store_true", default=False)
    p_gen.add_argument("--json", action="store_true")

    p_phrase = sub.add_parser("phrase", help="Generate a memorable passphrase.")
    p_phrase.add_argument("--words", type=int, default=4)
    p_phrase.add_argument("--sep", default="-")
    p_phrase.add_argument("--safe-symbols", action="store_true", default=True)
    p_phrase.add_argument("--json", action="store_true")

    p_suggest = sub.add_parser("suggest", help="Suggest passwords similar to a base word, but safer.")
    p_suggest.add_argument("base")
    p_suggest.add_argument("--count", type=int, default=5)
    p_suggest.add_argument("--length", type=int, default=14)
    p_suggest.add_argument("--similarity", type=float, default=0.55)
    p_suggest.add_argument("--json", action="store_true")

    p_serve = sub.add_parser("serve", help="Run FastAPI server.")
    p_serve.add_argument("--host", default=os.getenv("HOST", "0.0.0.0"))
    p_serve.add_argument("--port", type=int, default=int(os.getenv("PORT", "5005")))
    p_serve.add_argument("--reload", action="store_true")

    args = p.parse_args(argv)

    if args.cmd == "check":
        rep = check_password_strength(args.password, hints=args.hint, mode=args.mode)
        pol = policy_check(args.password, preset=args.preset)
        out: Dict[str, Any] = {"report": rep, "policy": pol}
        _dump(out, args.json)
        return

    if args.cmd == "policy":
        out = policy_check(args.password, preset=args.preset)
        _dump(out, args.json)
        return

    if args.cmd == "gen":
        pwd = generate_password(length=args.length, safe_symbols=args.safe_symbols, no_ambiguous=(not args.allow_ambiguous))
        out = {"password": pwd, "report": check_password_strength(pwd)}
        _dump(out, args.json)
        return

    if args.cmd == "phrase":
        phrase = generate_passphrase(num_words=args.words, separator=args.sep, safe_symbols=args.safe_symbols)
        out = {"passphrase": phrase, "report": check_password_strength(phrase)}
        _dump(out, args.json)
        return

    if args.cmd == "suggest":
        pwds = generate_similar_passwords(base=args.base, count=args.count, total_length=args.length, similarity=args.similarity, safe_symbols=True, no_ambiguous=True)
        out = [{"password": p, "report": check_password_strength(p, hints=[args.base])} for p in pwds]
        _dump(out, args.json)
        return

    if args.cmd == "serve":
        import uvicorn
        app = create_app()
        uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)
        return


if __name__ == "__main__":
    main()
