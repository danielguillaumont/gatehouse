"""Instruction-smuggling phrases shared by the poisoning and injection detectors.

These are *deterministic rules* and catch the common, published payload styles. A
paraphrase with no trigger words gets through (``docs/known-bypasses.md``).
"""

from __future__ import annotations

from gatehouse.events.schema import Severity
from gatehouse.inspect.rules import PatternRule, ci

_INJ = ("AML.T0051.001",)
_LLM01 = ("LLM01",)

INSTRUCTION_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "instruction-override",
        "tells the model to ignore its instructions",
        ci(
            r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?"
            r"(?:the\s+|your\s+|my\s+)?(?:previous|prior|above|earlier|preceding|existing|"
            r"system|original)\s+(?:instructions|prompts?|rules|directions|guidelines|"
            r"messages|context)\b"
        ),
        Severity.HIGH,
        ("ignore", "disregard", "forget", "override"),
        _INJ,
        _LLM01,
        skip_if_quoted=True,
    ),
    PatternRule(
        "role-reassignment",
        "tries to give the model a new role or mode",
        ci(
            r"\byou\s+are\s+now\s+(?:in\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|"
            r"jailbroken|developer\s+mode|god\s+mode|dan\b|evil)|"
            r"\b(?:enter|enable|activate)\s+(?:developer|god|debug)\s+mode\b"
        ),
        Severity.HIGH,
        ("you are now", "mode"),
        _INJ,
        _LLM01,
        skip_if_quoted=True,
    ),
    PatternRule(
        "chat-template-marker",
        "contains chat-template or role markers",
        ci(
            r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|\[/?INST\]|<</?SYS>>|"
            r"</?(?:tool_result|function_results|system-reminder)>"
        ),
        Severity.HIGH,
        (
            "<|",
            "[inst",
            "[/inst",
            "<<sys",
            "<</sys",
            "tool_result",
            "function_results",
            "system-reminder",
        ),
        _INJ,
        _LLM01,
    ),
    PatternRule(
        "concealment",
        "tells the model to hide something from the user",
        ci(
            r"\b(?:do\s+not|don'?t|never)\s+(?:tell|mention|inform|notify|alert|show)\s+"
            r"(?:the\s+user|this|that|it|anyone)\b|"
            r"\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?user\b|"
            r"\bkeep\s+(?:this|it)\s+(?:secret|hidden|confidential)\b|"
            r"\bcould\s+upset\s+the\s+user\b"
        ),
        Severity.HIGH,
        ("tell", "mention", "inform", "notify", "alert", "show", "without", "keep", "upset"),
        _INJ,
        _LLM01,
    ),
    PatternRule(
        "hidden-instruction-tag",
        "wraps text in a pseudo-privileged tag",
        ci(r"<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin|critical)\s*>"),
        Severity.HIGH,
        ("<",),
        _INJ,
        _LLM01,
    ),
    PatternRule(
        "addresses-the-model",
        "addresses the AI model directly with instructions",
        ci(
            r"\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+)?"
            r"(?:ai|assistant|model|llm|agent)\b|"
            r"\b(?:ai|llm)\s+(?:assistant|model|agent)\s*[:,]|"
            r"\bsystem\s+override\b|"
            r"\bnew\s+instructions\s+from\s+the\s+(?:developer|system|admin|operator)\b"
        ),
        Severity.HIGH,
        ("note", "message", "instruction", "ai ", "llm", "override"),
        _INJ,
        _LLM01,
    ),
    # Three rules, not one alternation: each has keywords that every match must contain,
    # so benign text that merely mentions "tool" never pays for a full regex pass.
    PatternRule(
        "tool-call-coercion",
        "pushes the model to call a tool",
        ci(
            r"\b(?:immediately|now|first|always)\s+(?:run|call|execute|invoke|use)\s+"
            r"(?:the\s+)?[`'\"]?[a-z][a-z0-9_\-]{1,63}[`'\"]?\s+tool\b"
        ),
        Severity.HIGH,
        ("immediately", "now", "first", "always"),
        ("AML.T0051.001", "AML.T0053"),
        ("LLM01", "LLM06"),
    ),
    PatternRule(
        "skip-confirmation",
        "tells the model not to ask the user for confirmation",
        ci(
            r"\b(?:do\s+not|don'?t|without)\s+ask(?:ing)?\s+(?:the\s+user\s+)?for\s+"
            r"(?:confirmation|permission|approval)\b"
        ),
        Severity.HIGH,
        ("confirmation", "permission", "approval"),
        ("AML.T0051.001", "AML.T0053"),
        ("LLM01", "LLM06"),
    ),
    PatternRule(
        "claimed-pre-approval",
        "claims the user has already approved an action",
        ci(r"\bhas\s+(?:already\s+)?pre-?approved\b"),
        Severity.HIGH,
        ("approved",),
        ("AML.T0051.001", "AML.T0053"),
        ("LLM01", "LLM06"),
    ),
)
