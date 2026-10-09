"""Best-effort PII detection and redaction with plain regular expressions.

Detectors: email, phone, credit_card (Luhn-checked), iban (mod-97 checked), ssn (US, dashed).

Limitations (by design — this is regex, not NER):
* Names, postal addresses, dates of birth, free-form identifiers are NOT detected.
* Phone detection needs >= 10 digits (>= 8 with a leading '+') written with
  separators or a '+'; unusual formats are missed, long digit runs may be over-matched.
* SSNs are only matched in the dashed ``123-45-6789`` form.
* Obfuscated values ("john at example dot com", digits spelled out, base64) pass through.
* Only text is scanned: images/audio/binary blobs are not inspected.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

DEFAULT_DETECTORS = ("credit_card", "iban", "ssn", "email", "phone")

_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
_CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")
_SSN = re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
_PHONE = re.compile(r"(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}(?:[ .-]\d{2,5}){1,5}(?![\w])")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        num = int("".join(str(int(c, 36)) for c in rearranged))
    except ValueError:
        return False
    return num % 97 == 1


def _card_ok(m: str) -> bool:
    digits = re.sub(r"\D", "", m)
    return 13 <= len(digits) <= 19 and luhn_ok(digits)


def _phone_ok(m: str) -> bool:
    n = sum(c.isdigit() for c in m)
    return (8 if m.startswith("+") else 10) <= n <= 15


_DETECTORS: dict[str, tuple[re.Pattern[str], Callable[[str], bool] | None]] = {
    "credit_card": (_CARD, _card_ok),
    "iban": (_IBAN, iban_ok),
    "ssn": (_SSN, None),
    "email": (_EMAIL, None),
    "phone": (_PHONE, _phone_ok),
}


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


def scan(text: str, detectors: Iterable[str] = DEFAULT_DETECTORS) -> list[Finding]:
    """Find PII spans. Detectors run in a fixed priority order; overlapping spans are dropped."""
    wanted = set(detectors)
    found: list[Finding] = []
    for kind in DEFAULT_DETECTORS:
        if kind not in wanted:
            continue
        pattern, validate = _DETECTORS[kind]
        for m in pattern.finditer(text):
            if validate and not validate(m.group()):
                continue
            if any(m.start() < f.end and f.start < m.end() for f in found):
                continue
            found.append(Finding(kind, m.start(), m.end()))
    return sorted(found, key=lambda f: f.start)


def redact_text(text: str, detectors: Iterable[str] = DEFAULT_DETECTORS) -> tuple[str, Counter[str]]:
    findings = scan(text, detectors)
    if not findings:
        return text, Counter()
    out, pos = [], 0
    for f in findings:
        out.append(text[pos : f.start])
        out.append(f"[REDACTED:{f.kind.upper()}]")
        pos = f.end
    out.append(text[pos:])
    return "".join(out), Counter(f.kind for f in findings)


def redact_value(value: Any, detectors: Iterable[str] = DEFAULT_DETECTORS) -> tuple[Any, Counter[str]]:
    """Recursively redact strings inside JSON-like data (dict keys are left alone)."""
    dets = tuple(detectors)
    counts: Counter[str] = Counter()

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            new, c = redact_text(v, dets)
            counts.update(c)
            return new
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, tuple):
            return tuple(walk(x) for x in v)
        return v

    return walk(value), counts


def summarize(counts: Counter[str]) -> str:
    return ", ".join(f"{k} x{n}" for k, n in sorted(counts.items()))
