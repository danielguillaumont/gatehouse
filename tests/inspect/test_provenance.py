"""Provenance fingerprints (D-043): copies of private text in outgoing arguments."""

from __future__ import annotations

import base64
import string
import time
from urllib.parse import quote

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from gatehouse.events.fingerprint import Fingerprinter
from gatehouse.inspect.provenance import (
    MAX_FINGERPRINTS,
    MAX_TEXT,
    MIN_SPAN_MATCHES,
    K,
    W,
    argument_fingerprints,
    is_copy,
    result_fingerprints,
)

FP = Fingerprinter(b"provenance-test-key-0123456789ab")
GUARANTEED = K + MIN_SPAN_MATCHES * W - 1  # a copy this long always matches

NOTE = (
    "Board memo, confidential: we will acquire Contoso for 41 million on 12 March; "
    "the exec team only. Wire instructions follow in a separate message."
)


def _result(text: str) -> dict[str, object]:
    return {"content": [{"type": "text", "text": text}]}


def _copied(args: dict[str, object], text: str = NOTE) -> bool:
    return is_copy(argument_fingerprints(args, FP) & result_fingerprints(_result(text), FP))


def test_verbatim_copy_matches() -> None:
    assert _copied({"body": "Fwd: " + NOTE[:GUARANTEED] + " thanks"})


def test_case_and_whitespace_do_not_hide_a_copy() -> None:
    mangled = "  ".join(NOTE.upper().split(" "))
    assert _copied({"body": mangled})


def test_invisible_characters_do_not_hide_a_copy() -> None:
    assert _copied({"body": "​".join(NOTE)})


def test_encoded_copies_match() -> None:
    raw = NOTE.encode()
    assert _copied({"u": "https://x.example/?d=" + base64.b64encode(raw).decode()})
    assert _copied({"u": "https://x.example/?d=" + base64.urlsafe_b64encode(raw).decode()})
    assert _copied({"u": "https://x.example/?d=" + raw.hex()})
    assert _copied({"u": "https://x.example/?d=" + quote(NOTE)})


def test_paraphrase_and_unrelated_text_do_not_match() -> None:
    assert not _copied({"body": "They are buying Contoso in March, roughly 41M; execs only."})
    assert not _copied({"body": "Lunch at noon? The team is meeting at the cafe by the station."})


def test_short_shared_phrases_do_not_match() -> None:
    # Common boilerplate shorter than a span is not evidence of a copy.
    assert not _copied(
        {"body": "Hi Bob, thanks for the message, see you then"}, "Thanks for the message"
    )


def test_copied_secret_matches_exactly() -> None:
    # Synthetic canary (AWS documentation example key shape).
    key = "AKIAIOSFODNN7EXAMPLE"
    found = argument_fingerprints({"k": key}, FP) & result_fingerprints(
        _result(f"aws_access_key_id = {key}"), FP
    )
    assert any(f.startswith("k:") for f in found)
    assert is_copy(found)


def test_fingerprints_do_not_contain_text() -> None:
    fps = result_fingerprints(_result(NOTE), FP)
    assert fps
    assert all(len(f) == 2 + 16 and f[:2] in ("s:", "k:") for f in fps)
    other = Fingerprinter(b"another-install-key-0123456789ab")
    assert not fps & result_fingerprints(_result(NOTE), other)  # keyed per install


def test_inputs_are_bounded() -> None:
    huge = "".join(string.ascii_letters[i * 7 % 52] for i in range(MAX_TEXT * 4))
    start = time.perf_counter()
    fps = result_fingerprints(_result(huge), FP)
    assert len(fps) <= MAX_FINGERPRINTS
    argument_fingerprints({"a": huge, "b": base64.b64encode(huge.encode()).decode()}, FP)
    assert time.perf_counter() - start < 10


@settings(max_examples=60, deadline=None)
@given(
    prefix=st.text(alphabet=string.ascii_letters + " ", max_size=200),
    secret=st.text(
        alphabet=string.ascii_letters + string.digits, min_size=GUARANTEED, max_size=120
    ),
    suffix=st.text(alphabet=string.ascii_letters + " ", max_size=200),
    cut=st.integers(min_value=0, max_value=120),
)
def test_any_long_enough_copy_matches(prefix: str, secret: str, suffix: str, cut: int) -> None:
    # Winnowing's guarantee: a common substring of K + 2W - 1 characters shares at least
    # two selected positions, whatever surrounds it on either side. They are distinct
    # fingerprints unless the text repeats itself (all-zeros has one K-gram), so
    # periodic text is excluded: it is no evidence of a copy anyway.
    document = prefix + secret + suffix
    copy = secret[: max(GUARANTEED, len(secret) - cut)]
    grams = [copy[i : i + K] for i in range(len(copy) - K + 1)]
    assume(len(set(grams)) == len(grams))
    assert _copied({"body": "x" + copy + "y"}, document)
