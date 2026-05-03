"""
Explanation Engine — uses Gemini API to turn structured security data into
human-readable prose.

IMPORTANT: Gemini is used ONLY for explanation and interpretation.
No AI output is ever used to make a security decision.
All inputs are already-computed facts from deterministic algorithms.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Gemini client — lazy import so the module loads even without the SDK
# ---------------------------------------------------------------------------

def _get_gemini_client():
    """Return a configured Gemini GenerativeModel, or raise ImportError."""
    try:
        import google.generativeai as genai  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "google-generativeai is not installed. "
            "Run: pip install google-generativeai"
        ) from exc

    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        raise EnvironmentError(
            "GEMINI_API_KEY environment variable is not set. "
            "Export it before using AI features:\n"
            "  set GEMINI_API_KEY=your_key_here   (Windows)\n"
            "  export GEMINI_API_KEY=your_key_here (Linux/macOS)"
        )

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        generation_config={
            "temperature": 0.1,      # Low temp → deterministic, factual output
            "top_p": 0.8,
            "max_output_tokens": 1024,
        },
        safety_settings=[
            {"category": "HARM_CATEGORY_HARASSMENT",       "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH",      "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT","threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT","threshold": "BLOCK_NONE"},
        ],
    )
    return model


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ExplainedPolicy:
    """AI explanation for a generated IAM policy."""
    function_id: str
    explanation: str          # Plain-English summary
    risk_summary: str         # One-sentence risk level statement
    key_concerns: List[str]   # Bullet-point issues
    recommendations: List[str]
    raw_input: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_id": self.function_id,
            "explanation": self.explanation,
            "risk_summary": self.risk_summary,
            "key_concerns": self.key_concerns,
            "recommendations": self.recommendations,
        }


@dataclass
class ExplainedAttackPath:
    """AI explanation for a single detected attack path."""
    path_id: str
    narrative: str            # Story-form description
    severity_rationale: str   # Why this risk level was assigned
    mitigation: str           # Concrete fix
    raw_input: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "narrative": self.narrative,
            "severity_rationale": self.severity_rationale,
            "mitigation": self.mitigation,
        }


@dataclass
class ExplainedRiskReport:
    """AI explanation for a full system risk assessment."""
    executive_summary: str
    top_risks: List[str]
    immediate_actions: List[str]
    positive_findings: List[str]
    raw_input: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "top_risks": self.top_risks,
            "immediate_actions": self.immediate_actions,
            "positive_findings": self.positive_findings,
        }


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PREAMBLE = (
    "You are a cloud security analyst assistant integrated into AdaPol, "
    "an automated cloud IAM policy tool. "
    "Your role is ONLY to explain and interpret security findings that have "
    "already been computed by deterministic algorithms. "
    "Never invent security decisions, scores, or recommendations not present "
    "in the data provided to you. "
    "Be concise, factual, and use plain English. "
    "Do NOT use markdown headers. Use numbered lists only when explicitly asked."
)

_POLICY_PROMPT = """{preamble}

You are given a JSON object describing an IAM policy generated for a cloud function.
Explain in plain English why this policy exists, what risks it carries, and what
the most important concerns are. Be specific: name the permissions and resources.

STRICT RULES:
- Only reference facts present in the JSON below.
- Do not invent permissions or resources not listed.
- Keep explanation under 120 words.
- Output exactly four sections separated by "|||":
  1. Plain-English explanation
  2. One-sentence risk summary
  3. Key concerns as a pipe-separated list (max 5 items)
  4. Recommendations as a pipe-separated list (max 5 items)

Policy JSON:
{policy_json}
"""

_ATTACK_PATH_PROMPT = """{preamble}

You are given a JSON object describing a detected attack path in a cloud
permission graph. Write a natural-language narrative that a developer or
security engineer could understand. Explain what an attacker could do by
exploiting this path and how to fix it.

STRICT RULES:
- Only reference nodes, permissions, and services present in the JSON.
- Keep narrative under 100 words.
- Output exactly three sections separated by "|||":
  1. Narrative (story-form attack description)
  2. Severity rationale (why this risk level was assigned, ≤ 40 words)
  3. Mitigation (concrete fix, ≤ 40 words)

Attack Path JSON:
{path_json}
"""

_RISK_REPORT_PROMPT = """{preamble}

You are given a JSON summary of a complete cloud security risk assessment.
Write an executive summary suitable for a team lead or security manager.

STRICT RULES:
- Only reference facts present in the JSON.
- Keep executive_summary under 100 words.
- Output exactly four sections separated by "|||":
  1. Executive summary
  2. Top risks as a pipe-separated list (max 5 items)
  3. Immediate actions as a pipe-separated list (max 5 items)
  4. Positive findings as a pipe-separated list (max 3 items, or "None" if absent)

Risk Assessment JSON:
{report_json}
"""


# ---------------------------------------------------------------------------
# Main explainer class
# ---------------------------------------------------------------------------

class AdaPolExplainer:
    """
    Converts deterministic security outputs into human-readable explanations
    using the Gemini API.

    Usage::

        explainer = AdaPolExplainer()

        # Explain a policy dict
        result = explainer.explain_policy("upload_handler", policy_dict)
        print(result.explanation)

        # Explain an attack path dict
        result = explainer.explain_attack_path(path.to_dict())
        print(result.narrative)

        # Explain a full risk report dict
        result = explainer.explain_risk_report(assessment.to_dict())
        print(result.executive_summary)
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        """
        Args:
            api_key: Gemini API key. Falls back to GEMINI_API_KEY env var.
        """
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key
        self._model = None   # Lazy initialise on first call
        logger.info("AdaPolExplainer created (model not yet loaded)")

    # ── public API ────────────────────────────────────────────────────────

    def explain_policy(
        self,
        function_id: str,
        policy_data: Dict[str, Any],
    ) -> ExplainedPolicy:
        """
        Generate a human-readable explanation for a generated IAM policy.

        Args:
            function_id: Identifier of the function this policy belongs to.
            policy_data: Policy dict (from adapol.export or policy.to_dict()).

        Returns:
            ExplainedPolicy with plain-English breakdown.
        """
        prompt = _POLICY_PROMPT.format(
            preamble=_SYSTEM_PREAMBLE,
            policy_json=json.dumps(policy_data, indent=2, default=str)[:3000],
        )
        raw = self._call_gemini(prompt)
        parts = self._split(raw, 4)

        return ExplainedPolicy(
            function_id=function_id,
            explanation=parts[0],
            risk_summary=parts[1],
            key_concerns=self._parse_list(parts[2]),
            recommendations=self._parse_list(parts[3]),
            raw_input=policy_data,
        )

    def explain_attack_path(
        self,
        path_data: Dict[str, Any],
    ) -> ExplainedAttackPath:
        """
        Convert a detected attack path into a natural-language narrative.

        Args:
            path_data: AttackPath.to_dict() output.

        Returns:
            ExplainedAttackPath with narrative, rationale, and mitigation.
        """
        prompt = _ATTACK_PATH_PROMPT.format(
            preamble=_SYSTEM_PREAMBLE,
            path_json=json.dumps(path_data, indent=2, default=str)[:2000],
        )
        raw = self._call_gemini(prompt)
        parts = self._split(raw, 3)

        return ExplainedAttackPath(
            path_id=path_data.get("path_id", "unknown"),
            narrative=parts[0],
            severity_rationale=parts[1],
            mitigation=parts[2],
            raw_input=path_data,
        )

    def explain_risk_report(
        self,
        report_data: Dict[str, Any],
    ) -> ExplainedRiskReport:
        """
        Summarise a full system risk assessment for a non-technical audience.

        Args:
            report_data: RiskAssessment.to_dict() output.

        Returns:
            ExplainedRiskReport with executive summary and action items.
        """
        # Trim node/policy lists to keep prompt manageable
        trimmed = {
            "summary": report_data.get("summary", {}),
            "top_attack_paths": report_data.get("top_attack_paths", [])[:5],
            "critical_nodes": report_data.get("critical_nodes", [])[:10],
            "recommendations": report_data.get("recommendations", []),
            "node_risks_sample": report_data.get("node_risks", [])[:5],
            "policy_risks_sample": report_data.get("policy_risks", [])[:5],
        }
        prompt = _RISK_REPORT_PROMPT.format(
            preamble=_SYSTEM_PREAMBLE,
            report_json=json.dumps(trimmed, indent=2, default=str)[:3000],
        )
        raw = self._call_gemini(prompt)
        parts = self._split(raw, 4)

        positive = self._parse_list(parts[3])
        if positive == ["None"] or positive == []:
            positive = ["No immediate positive findings noted."]

        return ExplainedRiskReport(
            executive_summary=parts[0],
            top_risks=self._parse_list(parts[1]),
            immediate_actions=self._parse_list(parts[2]),
            positive_findings=positive,
            raw_input=report_data,
        )

    def explain_drift_report(
        self,
        drift_data: Dict[str, Any],
    ) -> str:
        """
        Return a plain-English summary of a policy drift report.

        Args:
            drift_data: DriftReport.to_dict() output.

        Returns:
            Single paragraph explanation string.
        """
        prompt = (
            f"{_SYSTEM_PREAMBLE}\n\n"
            "Explain this policy drift report in plain English in ≤ 80 words. "
            "Highlight the most dangerous changes (high-risk additions, wildcards). "
            "Do NOT use bullet points or headers — write as a single paragraph.\n\n"
            f"Drift Report JSON:\n"
            + json.dumps(drift_data, indent=2, default=str)[:2500]
        )
        return self._call_gemini(prompt).strip()

    def explain_simulation_result(
        self,
        sim_data: Dict[str, Any],
    ) -> str:
        """
        Return a plain-English summary of a permission removal simulation.

        Args:
            sim_data: SimulationResult.to_dict() output.

        Returns:
            Single paragraph explanation string.
        """
        prompt = (
            f"{_SYSTEM_PREAMBLE}\n\n"
            "Explain this permission removal simulation result in plain English "
            "in ≤ 80 words. State clearly whether the removal is safe or dangerous "
            "and which functions would be affected. Single paragraph only.\n\n"
            f"Simulation JSON:\n"
            + json.dumps(sim_data, indent=2, default=str)[:2000]
        )
        return self._call_gemini(prompt).strip()

    # ── internal helpers ──────────────────────────────────────────────────

    def _call_gemini(self, prompt: str) -> str:
        """Send a prompt to Gemini and return the text response."""
        if self._model is None:
            self._model = _get_gemini_client()

        logger.debug("Sending prompt to Gemini (%d chars)", len(prompt))
        try:
            response = self._model.generate_content(prompt)
            text = response.text.strip()
            logger.debug("Gemini responded (%d chars)", len(text))
            return text
        except Exception as exc:
            logger.error("Gemini API error: %s", exc)
            raise RuntimeError(f"Gemini API call failed: {exc}") from exc

    @staticmethod
    def _split(text: str, expected: int) -> List[str]:
        """Split Gemini output on '|||' into expected number of parts."""
        parts = [p.strip() for p in text.split("|||")]
        # Pad with empty strings if model returned fewer sections
        while len(parts) < expected:
            parts.append("")
        return parts[:expected]

    @staticmethod
    def _parse_list(text: str) -> List[str]:
        """Parse a pipe-separated list string into a Python list."""
        if not text:
            return []
        items = [item.strip() for item in text.split("|") if item.strip()]
        return items if items else [text]
