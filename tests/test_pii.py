from __future__ import annotations

import mcp_types as types
import pytest

from agent_guard import pii
from agent_guard.policy import load_policy_data
from agent_guard.proxy import redact_result


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("mail me at jane.doe+test@example.co.uk please", "email"),
        ("card 4111 1111 1111 1111 exp 12/30", "credit_card"),
        ("card 4111-1111-1111-1111", "credit_card"),
        ("card 5555555555554444", "credit_card"),
        ("iban DE89 3704 0044 0532 0130 00 ok", "iban"),
        ("iban GB82WEST12345698765432", "iban"),
        ("ssn 123-45-6789", "ssn"),
        ("call +1 415 555 0134 now", "phone"),
        ("call (415) 555-0134 now", "phone"),
        ("call +44 20 7946 0958", "phone"),
        ("call 415.555.0134", "phone"),
    ],
)
def test_detects(text: str, kind: str) -> None:
    out, counts = pii.redact_text(text)
    assert counts == {kind: 1}, (out, counts)
    assert f"[REDACTED:{kind.upper()}]" in out


@pytest.mark.parametrize(
    "text",
    [
        "card 4111 1111 1111 1112",  # fails Luhn
        "order 1234567890123",  # 13 digits, fails Luhn
        "iban DE00 3704 0044 0532 0130 00",  # fails mod-97
        "ssn 000-12-3456",  # invalid area
        "on 2026-10-09 at 12:30",  # date / time
        "version 1.2.3 build 42",
        "short 555-0134",  # too few digits for a phone
        "user@localhost",  # no TLD
        "cus_ada001 refund 12.50",
    ],
)
def test_no_false_positive(text: str) -> None:
    out, counts = pii.redact_text(text)
    assert not counts, (out, counts)
    assert out == text


def test_luhn_and_iban_helpers() -> None:
    assert pii.luhn_ok("4111111111111111")
    assert not pii.luhn_ok("4111111111111112")
    assert pii.iban_ok("DE89370400440532013000")
    assert not pii.iban_ok("DE89370400440532013001")


def test_detector_selection() -> None:
    text = "a@example.com 123-45-6789"
    out, counts = pii.redact_text(text, ["ssn"])
    assert counts == {"ssn": 1}
    assert "a@example.com" in out


def test_card_not_reported_as_phone() -> None:
    _, counts = pii.redact_text("4111 1111 1111 1111")
    assert counts == {"credit_card": 1}


def test_redact_value_recurses_and_keeps_keys() -> None:
    data = {"email": "x@example.com", "nested": [{"phone": "+1 415 555 0134"}, 42, None], "ok": "fine"}
    out, counts = pii.redact_value(data)
    assert out == {"email": "[REDACTED:EMAIL]", "nested": [{"phone": "[REDACTED:PHONE]"}, 42, None], "ok": "fine"}
    assert counts == {"email": 1, "phone": 1}


def test_redact_tool_result_text_and_structured() -> None:
    result = types.CallToolResult(
        content=[types.TextContent(type="text", text='{"email": "ada@example.com"}')],
        structured_content={"email": "ada@example.com"},
    )
    new, counts = redact_result(result, list(pii.DEFAULT_DETECTORS))
    assert counts == {"email": 1}
    assert "ada@example.com" not in new.content[0].text  # type: ignore[union-attr]
    assert new.structured_content == {"email": "[REDACTED:EMAIL]"}
    assert result.structured_content == {"email": "ada@example.com"}  # original untouched


def test_pii_policy_first_match_and_yaml_off() -> None:
    policy = load_policy_data(
        {
            "pii": [
                {"tools": "payments.lookup_customer", "arguments": False, "results": "block"},
                {"tools": "*", "arguments": "redact"},
            ]
        }
    )
    first = policy.pii_for("payments.lookup_customer")
    assert first and first.arguments == "off" and first.results == "block"
    other = policy.pii_for("files.write_file")
    assert other and other.arguments == "redact" and other.results == "redact"
