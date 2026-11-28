"""Model-based detectors (classifiers) behind one async interface (ADR-0007, D-050).

Unlike the rule detectors in ``gatehouse.inspect``, a classifier does I/O: it runs a
local ONNX model, calls Azure Prompt Shields, or asks a local Ollama model. So this
package keeps the pure parts (``base``: which text is sent, how a verdict becomes a
finding) apart from the backends (``backends``) and the runner that applies the latency
budget (``runner``). The router decides what a verdict does, from the policy's ``mode``.
"""
