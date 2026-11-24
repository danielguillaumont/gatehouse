from __future__ import annotations

import pytest

from gatehouse.inspect.secrets import SECRET_RULES, detect_secrets, find_secrets, mask, redact_text

# Synthetic values with the right shape. None of these are real credentials.
POSITIVES = {
    "private-key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "aws-access-key-id": "AKIAIOSFODNN7EXAMPLE",
    "aws-secret-access-key": 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    "github-token": "ghp_" + "a" * 36,
    "github-fine-grained-pat": "github_pat_" + "B" * 22 + "_" + "c" * 59,
    "gitlab-pat": "glpat-" + "x" * 20,
    "slack-token": "xoxb-" + "1234567890-abcdefghij",
    "slack-webhook": "https://hooks.slack.com/services/T0000/B0000/" + "X" * 24,
    "stripe-live-key": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "google-api-key": "AIza" + "S" * 35,
    "anthropic-api-key": "sk-ant-api03-" + "z" * 40,
    "openai-api-key": "sk-proj-" + "q" * 40,
    "azure-storage-account-key": "DefaultEndpointsProtocol=https;AccountName=x;AccountKey="
    + "A" * 86
    + "==",
    "azure-sas-signature": "https://x.blob.core.windows.net/c?sv=2022-11-02&sig=" + "a%2Bb" * 10,
    "entra-client-secret": "abc8Q~" + "d" * 34,
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "url-credentials": "postgres://admin:s3cr3tpw@db.internal:5432/app",
    "generic-assignment": "api_key: 9f8e7d6c5b4a3210",
}

NEGATIVES = [
    "The weather in Paris is sunny, 21C.",
    "AKIA is a prefix but AKIA123 is too short",
    "ghp_short",
    "sk-learn is a library",
    "see https://example.com/docs?page=2&sort=asc",
    "user@example.com wrote: thanks!",
    "password reset instructions were sent",
    "eyJ not a token",
    "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",  # sha1-like hex, no context
]


def test_every_rule_has_a_positive_example() -> None:
    assert {r.rule_id for r in SECRET_RULES} == set(POSITIVES)


@pytest.mark.parametrize(("rule_id", "text"), sorted(POSITIVES.items()))
def test_positive(rule_id: str, text: str) -> None:
    ids = {m.rule.rule_id for m in find_secrets(f"prefix {text} suffix")}
    assert rule_id in ids


@pytest.mark.parametrize("text", NEGATIVES)
def test_negative(text: str) -> None:
    assert find_secrets(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "tool_ghp_" + "a" * 36,  # glued to an identifier: \b would miss this
        "GITHUB_TOKEN=ghp_" + "a" * 36,
        "key_AKIAIOSFODNN7EXAMPLE",
        "db_password = hunter2hunter2",
    ],
)
def test_secrets_glued_to_identifiers(text: str) -> None:
    assert find_secrets(text)


def test_mask_never_reveals_middle() -> None:
    value = "ghp_" + "a" * 36
    masked = mask(value)
    assert masked.startswith("ghp_") and masked.endswith("aaaa")
    assert value not in masked and "*" in masked
    assert mask("short") == "*****"


def test_redact_text_replaces_every_secret() -> None:
    a = "AKIAIOSFODNN7EXAMPLE"
    b = "ghp_" + "b" * 36
    out = redact_text(f"keys {a} and {b} end")
    assert a not in out and b not in out
    assert out.startswith("keys ") and out.endswith(" end")


def test_detect_secrets_walks_nested_values_and_keys() -> None:
    args = {
        "outer": {"list": ["fine", {"deep": "AKIAIOSFODNN7EXAMPLE"}]},
        "AKIAIOSFODNN7EXAMPL2": 1,
    }
    findings = detect_secrets(args, "arguments", fingerprint=lambda v: "fp")
    locations = {f.location for f in findings}
    assert "arguments.outer.list[1].deep" in locations
    assert "arguments.{key}" in locations
    assert all(f.fingerprint == "fp" for f in findings)
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.summary for f in findings)


def test_patterns_are_fast_on_adversarial_input() -> None:
    import time

    hostile = ("aws" + " " * 30 + "secret" + "=" * 4) * 5000 + "a" * 100_000
    start = time.perf_counter()
    find_secrets(hostile)
    assert time.perf_counter() - start < 2.0
