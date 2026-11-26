"""The scrubber removes real PII without destroying timestamps and IDs (#205)."""
import pytest

from services.pii_scrubber import scrub_text

KEPT = [
    "ts=1732600000123 level=error",          # epoch milliseconds (13 digits)
    "epoch=1732600000",                      # epoch seconds (10 digits)
    '{"timestamp": 1764151200000, "msg": "timeout"}',
    "took 1234567890123 ns",                 # nanosecond duration
    "order 12345678901234 ok",               # long numeric ID
    "id 2026112610 ok",
    "visa-like 4111111111111112 fails luhn",
    "trace_id=4b6f8c1e9d2a7f3c span=00f067aa0ba902b7",
    "build 1.2.3.4567890123456",
    "2026-11-26 10:15:30.123 GET /health 200",
    "pid 123456 rss 9876543210",
]


@pytest.mark.parametrize("text", KEPT)
def test_timestamps_and_ids_are_kept(text):
    assert scrub_text(text) == text


@pytest.mark.parametrize("text, secret", [
    ("card 4111 1111 1111 1111 declined", "4111 1111 1111 1111"),   # Visa test number
    ("card 4111111111111111", "4111111111111111"),
    ("mc 5500-0000-0000-0004", "5500-0000-0000-0004"),               # Mastercard
    ("mc2 2223000048400011", "2223000048400011"),                    # Mastercard 2-series
    ("amex 378282246310005", "378282246310005"),                     # Amex (15)
    ("disc 6011111111111117", "6011111111111117"),                   # Discover
    ("jcb 3530111333300000", "3530111333300000"),                    # JCB
])
def test_real_card_numbers_are_redacted(text, secret):
    out = scrub_text(text)
    assert secret not in out and "[REDACTED_CARD]" in out


@pytest.mark.parametrize("text, secret", [
    ("call 555-123-4567", "555-123-4567"),
    ("call (555) 123-4567", "123-4567"),
    ("+1 555 123 4567", "555 123 4567"),
    ("tel 555.123.4567.", "555.123.4567"),
])
def test_formatted_phone_numbers_are_redacted(text, secret):
    out = scrub_text(text)
    assert secret not in out and "[REDACTED_PHONE]" in out


def test_ssn_and_email_still_redacted():
    out = scrub_text("ssn 123-45-6789 mail a.b@example.com")
    assert "123-45-6789" not in out and "a.b@example.com" not in out
