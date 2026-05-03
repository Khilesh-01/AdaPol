"""
AI Module — Gemini-powered explanation and natural-language interface for AdaPol.

IMPORTANT: AI is used ONLY for explanation, interpretation, and user interaction.
All core security decisions (risk scoring, attack detection, policy generation)
are made exclusively by deterministic algorithms in the security_graph and
simulation modules.

Components
----------
explainer     — Converts policies, risk reports, and attack paths to readable prose
nl_interface  — Translates natural-language commands into structured CLI calls
"""

from .explainer import (
    AdaPolExplainer,
    ExplainedPolicy,
    ExplainedAttackPath,
    ExplainedRiskReport,
)

from .nl_interface import (
    NLInterface,
    ParsedCommand,
    CommandIntent,
)

__all__ = [
    # Explainer
    "AdaPolExplainer",
    "ExplainedPolicy",
    "ExplainedAttackPath",
    "ExplainedRiskReport",
    # NL Interface
    "NLInterface",
    "ParsedCommand",
    "CommandIntent",
]
