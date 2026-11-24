"""Security events: schema (``schema``), redaction, emitter and sinks.

Intentionally no re-exports: ``inspect`` imports ``events.schema`` and ``events.emitter``
imports ``inspect``, so eager imports here would create a cycle.
"""
