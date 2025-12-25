# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import math
import re
import secrets
import string
import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional


# -------------------- Character sets --------------------
DEFAULT_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
SAFE_SYMBOLS = "!@#$%^&*_-+="  # أقل مشاكل مع المواقع
AMBIGUOUS = set("O0oIl1|`'\"")


# -------------------- Common patterns / weak lists --------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey",
    "passw0rd", "shadow", "123123", "654321", "admin",
    "welcome", "login", "princess", "football", "qwerty123",
    "111111", "000000", "123456789", "qwertyuiop"
}

KEYBOARD_SEQS = ["qwerty", "asdf", "zxcv", "qaz", "wsx", "edc"]
MONTHS = ["january","february","march","april","may","june","july","august","september","october","november","december"]
COMMON_WORDS = {
    # قاموس صغير جداً (بس يعطي إشارات)، مش بديل عن zxcvbn
    "love","hello","welcome","admin","user","test","home","secret","god","king","queen",
    "password","dragon","football","ilove","monkey","letmein","sunshine","flower","computer"
} | set(MONTHS)


# -------------------- Helpers --------------------
def _has_upper(s: str) -> bool: return bool(re.search(r"[A-Z]", s))
def _has_lower(s: str) -> bool: return bool(re.search(r"[a-z]", s))
def _has_digit(s: str) -> bool: return bool(re.search(r"[0-9]", s))
def _has_symbol(s: str) -> bool: return bool(re.search(r"[^A-Za-z0-9]", s))

def _unique_ratio(s: str) -> float:
    return (len(set(s)) / len(s)) if s else 0.0

def _max_run_length(s: str) -> int:
    # أطول تكرار متتالٍ لنفس الحرف (aaaa = 4)
    if not s:
        return 0
    best = 1
    run = 1
    for i in range(1, len(s)):
        if s[i] == s[i-1]:
            run += 1
            best = max(best, run)
        else:
            run = 1
    return best

def _contains_sequence(s: str, min_len: int = 4) -> bool:
    # تسلسلات رقمية أو حرفية: abcd, 1234 (صعود/نزول)
    if len(s) < min_len:
        return False
    lower = s.lower()

    # تحقق تسلسل أرقام
    digits = re.findall(r"\d+", lower)
    for chunk in digits:
        if len(chunk) >= min_len:
            inc = all(ord(chunk[i])+1 == ord(chunk[i+1]) for i in range(len(chunk)-1))
            dec = all(ord(chunk[i])-1 == ord(chunk[i+1]) for i in range(len(chunk)-1))
            if inc or dec:
                return True

    # تحقق تسلسل أحرف
    letters = re.findall(r"[a-z]+", lower)
    for chunk in letters:
        if len(chunk) >= min_len:
            inc = all(ord(chunk[i])+1 == ord(chunk[i+1]) for i in range(len(chunk)-1))
            dec = all(ord(chunk[i])-1 == ord(chunk[i+1]) for i in range(len(chunk)-1))
            if inc or dec:
                return True
    return False

def _contains_keyboard_pattern(s: str) -> bool:
    low = s.lower()
    return any(pat in low for pat in KEYBOARD_SEQS)

def _contains_common_word(s: str) -> bool:
    low = s.lower()
    return any(w in low for w in COMMON_WORDS)

def _charset_size(s: str) -> int:
    size = 0
    if _has_lower(s): size += 26
    if _has_upper(s): size += 26
    if _has_digit(s): size += 10
    if _has_symbol(s): size += 32  # تقريب
    return size

def estimate_entropy_bits(password: str) -> float:
    """
    Shannon-ish upper bound approximation using charset size:
    entropy ≈ log2(charset_size^len) = len * log2(charset_size)
    ثم نخصم خصم بسيط إذا في تكرار/أنماط شائعة.
    """
    if not password:
        return 0.0
    cs = _charset_size(password)
    if cs <= 0:
        return 0.0
    base = len(password) * math.log2(cs)

    # خصومات بسيطة (تقريبية)
    penalty = 0.0
    if _max_run_length(password) >= 3:
        penalty += 8.0
    if _contains_sequence(password):
        penalty += 10.0
    if _contains_keyboard_pattern(password):
        penalty += 10.0
    if _contains_common_word(password):
        penalty += 6.0
    if password.lower() in COMMON_PASSWORDS:
        penalty += 20.0

    return max(0.0, base - penalty)

def estimate_crack_time(password: str, mode: str = "offline") -> str:
    """
    تقدير تقريبي مبني على entropy:
    guesses ~ 2^entropy
    """
    ent = estimate_entropy_bits(password)
    if ent <= 0:
        return "Unknown"

    guesses = 2 ** ent
    gps = 10 if mode.lower() == "online" else 1_000_000_000  # online vs offline
    seconds = guesses / gps

    if seconds < 60:
        return "Less than 1 minute"
    if seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    if seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    if seconds < 31536000:
        return f"{int(seconds / 86400)} days"

    years = int(seconds / 31536000)
    if years > 1_000_000_000:
        return "More than 1 billion years"
    return f"{years:,} years"


# -------------------- Strength checker (improved) --------------------
def check_password_strength(password: str, hints: Optional[List[str]] = None) -> Dict:
    """
    Score out of 10 + entropy bits + detailed feedback.
    hints: كلمات مرتبطة بالمستخدم (اسم/يوزر/إيميل) للتأكد إنها مش موجودة بالباسورد.
    """
    hints = [h.lower() for h in (hints or []) if h.strip()]
    feedback: List[str] = []
    score = 0

    if not password:
        return {
            "score": 0, "percentage": 0, "strength": "Very Weak",
            "entropy_bits": 0.0,
            "feedback": ["Empty password."],
            "length": 0, "unique_chars": 0,
            "offline_crack": "Unknown", "online_crack": "Unknown"
        }

    length = len(password)
    unique_chars = len(set(password))
    uniq_ratio = _unique_ratio(password)
    max_run = _max_run_length(password)

    # ---- Length (0..3) ----
    if length >= 10: score += 1
    else: feedback.append("Use at least 10 characters (better: 14+).")

    if length >= 14: score += 1
    else: feedback.append("Consider 14+ characters for strong security.")

    if length >= 20: score += 1  # passphrase territory
    else: feedback.append("20+ characters (passphrase) is excellent if you can.")

    # ---- Character diversity (0..4) ----
    classes = 0
    if _has_upper(password): classes += 1
    else: feedback.append("Add uppercase letters (A-Z).")

    if _has_lower(password): classes += 1
    else: feedback.append("Add lowercase letters (a-z).")

    if _has_digit(password): classes += 1
    else: feedback.append("Add digits (0-9).")

    if _has_symbol(password): classes += 1
    else: feedback.append("Add symbols (e.g., !@#$...).")

    score += min(4, classes)

    # ---- Uniqueness / repetition (0..1) ----
    if uniq_ratio >= 0.7 and max_run <= 2:
        score += 1
    else:
        if max_run >= 3:
            feedback.append("Avoid repeating the same character 3+ times in a row.")
        if uniq_ratio < 0.7:
            feedback.append("Increase character variety (avoid lots of repeats).")

    # ---- Pattern penalties (0..2 bonus/penalty style) ----
    # نعطي نقطتين إضافية إذا ما في أنماط ضعيفة، وإلا ننقص
    pattern_score = 2

    if password.lower() in COMMON_PASSWORDS:
        feedback.append("This is a very common password. Avoid it completely.")
        pattern_score -= 2

    if _contains_keyboard_pattern(password):
        feedback.append("Avoid keyboard patterns (qwerty/asdf...).")
        pattern_score -= 1

    if _contains_sequence(password):
        feedback.append("Avoid sequences like 1234 or abcd.")
        pattern_score -= 1

    if _contains_common_word(password):
        feedback.append("Avoid common words/month names inside the password.")
        pattern_score -= 1

    for h in hints:
        if h and len(h) >= 3 and h in password.lower():
            feedback.append("Avoid including personal info (name/username/email) inside the password.")
            pattern_score -= 2
            break

    score += max(0, pattern_score)

    # Clamp score 0..10
    score = max(0, min(10, score))
    percentage = int((score / 10) * 100)

    entropy_bits = round(estimate_entropy_bits(password), 2)

    if score <= 2:
        strength = "Very Weak"
    elif score <= 4:
        strength = "Weak"
    elif score <= 7:
        strength = "Medium"
    else:
        strength = "Strong"

    # تنظيف feedback من التكرار
    dedup = []
    seen = set()
    for f in feedback:
        if f not in seen:
            seen.add(f)
            dedup.append(f)

    if strength == "Strong" and not dedup:
        dedup.append("Excellent password.")

    return {
        "score": score,
        "percentage": percentage,
        "strength": strength,
        "entropy_bits": entropy_bits,
        "feedback": dedup,
        "length": length,
        "unique_chars": unique_chars,
        "offline_crack": estimate_crack_time(password, "offline"),
        "online_crack": estimate_crack_time(password, "online"),
    }


# -------------------- Password generators --------------------
def _build_pools(uppercase: bool, lowercase: bool, numbers: bool, symbols: bool,
    safe_symbols: bool, no_ambiguous: bool) -> List[str]:
    pools = []
    if uppercase:
        pools.append(string.ascii_uppercase)
    if lowercase:
        pools.append(string.ascii_lowercase)
    if numbers:
        pools.append(string.digits)
    if symbols:
        pools.append(SAFE_SYMBOLS if safe_symbols else DEFAULT_SYMBOLS)

    if not pools:
        raise ValueError("Enable at least one character category.")

    if no_ambiguous:
        pools = ["".join(ch for ch in pool if ch not in AMBIGUOUS) for pool in pools]

    # بعد إزالة ambiguous ممكن يصير pool فاضي
    for p in pools:
        if not p:
            raise ValueError("A character pool became empty (try disabling --no-ambiguous).")
    return pools


def generate_password(length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    safe_symbols: bool = False,
    no_ambiguous: bool = False) -> str:
    if length < 10:
        raise ValueError("Length must be 10 or greater (recommended 14+).")

    pools = _build_pools(uppercase, lowercase, numbers, symbols, safe_symbols, no_ambiguous)

    if length < len(pools):
        raise ValueError("Length is too small for the selected categories.")

    # force one char from each pool
    pwd = [secrets.choice(pool) for pool in pools]

    all_chars = "".join(pools)
    pwd += [secrets.choice(all_chars) for _ in range(length - len(pwd))]

    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def generate_passphrase(num_words: int = 4,
                        separator: str = "-",
                        add_number: bool = True,
                        add_symbol: bool = True,
                        safe_symbols: bool = True) -> str:
    # قائمة كلمات صغيرة داخل الكود (لو بدك أكبر، ممكن نخليها ملف خارجي)
    WORDS = [
        "canyon","violet","laser","otter","planet","silver","matrix","falcon","ember","rocket",
        "oasis","nebula","panda","tiger","comet","saffron","coral","zenith","lunar","nova",
        "atlas","cipher","breeze","harbor","pixel","quartz","ranger","summit","tunnel","whisper"
    ]
    if num_words < 3:
        raise ValueError("Use at least 3 words (recommended 4-6).")

    words = [secrets.choice(WORDS) for _ in range(num_words)]
    phrase = separator.join(words)

    if add_number:
        phrase += str(secrets.randbelow(90) + 10)  # 10..99

    if add_symbol:
        symset = SAFE_SYMBOLS if safe_symbols else DEFAULT_SYMBOLS
        phrase += secrets.choice(symset)

    # اضمن وجود upper/lower (نرفع أول حرف عشوائي)
    chars = list(phrase)
    idx = secrets.randbelow(len(chars))
    if chars[idx].isalpha():
        chars[idx] = chars[idx].upper()
    return "".join(chars)


# -------------------- Similar-to-word generator (kept + improved constraints) --------------------
LEET_MAP = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "g": ["9"],
}

def mutate_word(base: str, similarity: int = 3) -> str:
    if not base:
        return base

    flip_chance = {1: 20, 2: 35, 3: 50, 4: 65, 5: 80}[similarity]
    leet_chance = {1: 10, 2: 20, 3: 35, 4: 50, 5: 65}[similarity]
    sep_chance  = {1: 5,  2: 10, 3: 20, 4: 30, 5: 40}[similarity]

    out = []
    for ch in base:
        if ch.isalpha():
            out.append(ch.upper() if secrets.randbelow(100) < flip_chance else ch.lower())
        else:
            out.append(ch)
    word = "".join(out)

    out2 = []
    for ch in word:
        low = ch.lower()
        if low in LEET_MAP and secrets.randbelow(100) < leet_chance:
            out2.append(secrets.choice(LEET_MAP[low]))
        else:
            out2.append(ch)
    word = "".join(out2)

    if len(word) >= 4 and secrets.randbelow(100) < sep_chance:
        pos = secrets.randbelow(len(word) - 1) + 1
        word = word[:pos] + secrets.choice(["_", "-", "."]) + word[pos:]

    return word


def inject_randomness(s: str, extra_chars: int, symbols: str) -> str:
    alphabet = string.ascii_letters + string.digits + symbols
    chars = list(s)
    for _ in range(extra_chars):
        pos = secrets.randbelow(len(chars) + 1)
        chars.insert(pos, secrets.choice(alphabet))
    return "".join(chars)


def generate_similar_passwords(base_word: str,
    total_length: int = 16,
    count: int = 5,
    similarity: int = 3,
    safe_symbols: bool = False,
    no_ambiguous: bool = False) -> List[str]:
    base_word = base_word.strip()
    if not base_word:
        raise ValueError("Base word cannot be empty.")
    if not (1 <= similarity <= 5):
        raise ValueError("Similarity must be between 1 and 5.")
    if total_length < 12:
        raise ValueError("Total length must be at least 12 (recommended 16).")
    if count < 1 or count > 20:
        raise ValueError("Count must be between 1 and 20.")

    symbols = SAFE_SYMBOLS if safe_symbols else DEFAULT_SYMBOLS
    inject_count = {1: 4, 2: 4, 3: 5, 4: 6, 5: 7}[similarity]

    results = []
    attempts = 0
    while len(results) < count and attempts < 400:
        attempts += 1
        mutated = mutate_word(base_word, similarity=similarity)

        if len(mutated) > total_length:
            mutated = mutated[:total_length]

        candidate = inject_randomness(mutated, extra_chars=inject_count, symbols=symbols)

        # adjust length
        alphabet = string.ascii_letters + string.digits + symbols
        if len(candidate) < total_length:
            candidate += "".join(secrets.choice(alphabet) for _ in range(total_length - len(candidate)))
        else:
            candidate = candidate[:total_length]

        if no_ambiguous:
            candidate = "".join(ch for ch in candidate if ch not in AMBIGUOUS)
            if len(candidate) < total_length:
                candidate += "".join(secrets.choice(alphabet) for _ in range(total_length - len(candidate)))
            candidate = candidate[:total_length]

        # enforce 4 classes
        if (_has_upper(candidate) and _has_lower(candidate) and _has_digit(candidate) and _has_symbol(candidate)):
            if candidate not in results:
                results.append(candidate)

    if not results:
        raise ValueError("Could not generate valid passwords with the given constraints.")
    return results


# -------------------- Reporting --------------------
def print_report(result: Dict) -> None:
    print("Password Report:")
    print(f"  - Strength: {result['strength']} ({result['percentage']}%)  score={result['score']}/10")
    print(f"  - Length: {result['length']}  | Unique chars: {result['unique_chars']}")
    print(f"  - Entropy (est.): {result['entropy_bits']} bits")
    print(f"  - Crack time (offline): {result['offline_crack']}")
    print(f"  - Crack time (online):  {result['online_crack']}")

    # bar
    bar_len = 30
    filled = int(bar_len * result["percentage"] / 100)
    bar = "#" * filled + "." * (bar_len - filled)
    print(f"  - Meter: [{bar}]")

    if result["feedback"]:
        print("\nRecommendations:")
        for f in result["feedback"]:
            print(f"  * {f}")




# --- Additions: policy presets + privacy-preserving fingerprint + attested report helpers ---

from typing import Any

DEFAULT_POLICIES: Dict[str, Dict[str, Any]] = {
    # NIST-ish: prefer length, avoid silly rules. Still blocks common/guessable patterns.
    "nist": {
        "min_length": 14,
        "require_upper": False,
        "require_lower": False,
        "require_digit": False,
        "require_symbol": False,
        "max_run": 3,
        "block_sequences": True,
        "block_keyboard_patterns": True,
        "block_common_passwords": True,
        "block_common_words": True,
    },
    "strong": {
        "min_length": 14,
        "require_upper": True,
        "require_lower": True,
        "require_digit": True,
        "require_symbol": True,
        "max_run": 3,
        "block_sequences": True,
        "block_keyboard_patterns": True,
        "block_common_passwords": True,
        "block_common_words": True,
    },
    "basic": {
        "min_length": 10,
        "require_upper": False,
        "require_lower": True,
        "require_digit": True,
        "require_symbol": False,
        "max_run": 4,
        "block_sequences": True,
        "block_keyboard_patterns": True,
        "block_common_passwords": True,
        "block_common_words": True,
    },
}

def policy_check(password: str, policy: Dict[str, Any] | None = None, preset: str | None = "nist") -> Dict[str, Any]:
    """
    Returns: {"passed": bool, "issues": [{"code": str, "message": str, "severity": str}], "policy": {...}}
    """
    if policy is None:
        policy = DEFAULT_POLICIES.get(preset or "nist", DEFAULT_POLICIES["nist"]).copy()

    issues: List[Dict[str, str]] = []

    def issue(code: str, message: str, severity: str = "medium") -> None:
        issues.append({"code": code, "message": message, "severity": severity})

    min_length = int(policy.get("min_length", 14))
    if len(password) < min_length:
        issue("length.too_short", f"Password length is {len(password)}; minimum is {min_length}.", "high")

    if bool(policy.get("require_upper")) and not _has_upper(password):
        issue("class.missing_upper", "Missing uppercase letter.", "medium")
    if bool(policy.get("require_lower")) and not _has_lower(password):
        issue("class.missing_lower", "Missing lowercase letter.", "medium")
    if bool(policy.get("require_digit")) and not _has_digit(password):
        issue("class.missing_digit", "Missing digit.", "medium")
    if bool(policy.get("require_symbol")) and not _has_symbol(password):
        issue("class.missing_symbol", "Missing symbol.", "medium")

    max_run = int(policy.get("max_run", 3))
    if _max_run_length(password) >= max_run:
        issue("pattern.repetition", f"Contains repeated character runs (>= {max_run}).", "medium")

    if bool(policy.get("block_sequences")) and _contains_sequence(password):
        issue("pattern.sequence", "Contains sequential pattern (e.g., 1234/abcd).", "high")

    if bool(policy.get("block_keyboard_patterns")) and _contains_keyboard_pattern(password):
        issue("pattern.keyboard", "Contains keyboard pattern (e.g., qwerty/asdf).", "high")

    if bool(policy.get("block_common_words")) and _contains_common_word(password):
        issue("pattern.common_word", "Contains common word/month name.", "medium")

    if bool(policy.get("block_common_passwords")) and password.lower() in COMMON_PASSWORDS:
        issue("blocklist.common_password", "Password is a known common password.", "high")

    return {"passed": len(issues) == 0, "issues": issues, "policy": policy}

def password_fingerprint(password: str, secret: str) -> str:
    """
    Privacy-preserving token to detect password reuse WITHOUT storing the password.
    Computes HMAC-SHA256(secret, password) and returns a short base64url token.
    """
    if not secret:
        raise ValueError("secret is required")
    mac = hmac.new(secret.encode("utf-8"), password.encode("utf-8"), hashlib.sha256).digest()
    # 16 bytes is enough for a stable non-reversible tag in most apps
    token = base64.urlsafe_b64encode(mac[:16]).decode("ascii").rstrip("=")
    return token

def safe_report_payload(password: str, hints: List[str] | None = None, preset: str = "nist") -> Dict[str, Any]:
    """
    Generate a report WITHOUT returning/storing the password.
    Includes:
      - strength report
      - policy check
    """
    report = check_password_strength(password, hints=hints or [])
    pol = policy_check(password, preset=preset)
    # Remove raw password from any fields (there shouldn't be any, but be safe)
    return {"report": report, "policy": pol}
