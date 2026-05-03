"""
Natural-Language Interface — translates free-form user queries into structured
AdaPol CLI command specifications using the Gemini API.

IMPORTANT: AI output from this module is NEVER executed directly.
The user always sees the translated command before it runs, ensuring
no security decision is made autonomously by the AI.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Intent taxonomy — exhaustive list of supported operations
# ---------------------------------------------------------------------------

class CommandIntent(Enum):
    """Every CLI command the NL interface can suggest."""
    # Core analysis
    ANALYZE           = "analyze"
    DEMO              = "demo"
    GENERATE_SAMPLE   = "generate_sample"
    VALIDATE          = "validate"
    REPORT            = "report"

    # Graph / risk
    ANALYZE_ATTACK_PATHS = "analyze_attack_paths"
    SHOW_RISK_REPORT     = "show_risk_report"

    # Drift detection
    SAVE_POLICY_SNAPSHOT = "save_policy_snapshot"
    COMPARE_POLICY       = "compare_policy"

    # Simulation
    SIMULATE_REMOVAL  = "simulate_removal"
    SIMULATE_BATCH    = "simulate_batch"
    PREDICT_FAILURES  = "predict_failures"

    # AI (explain)
    EXPLAIN_POLICY       = "explain_policy"
    EXPLAIN_ATTACK_PATHS = "explain_attack_paths"
    EXPLAIN_RISK_REPORT  = "explain_risk_report"
    EXPLAIN_DRIFT        = "explain_drift"
    EXPLAIN_SIMULATION   = "explain_simulation"

    UNKNOWN = "unknown"


@dataclass
class ParsedCommand:
    """The AI's interpretation of a natural-language query."""
    intent: CommandIntent
    cli_command: str              # Full shell command string to run
    args: Dict[str, str]          # Parsed flag → value pairs
    confidence: float             # 0.0–1.0
    explanation: str              # Why the AI mapped to this command
    alternatives: List[str]       # Other commands that might apply
    requires_files: List[str]     # File paths the command needs (may be placeholders)
    raw_query: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent": self.intent.value,
            "cli_command": self.cli_command,
            "args": self.args,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "alternatives": self.alternatives,
            "requires_files": self.requires_files,
            "raw_query": self.raw_query,
        }


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_NL_SYSTEM = (
    "You are a CLI assistant for AdaPol, a cloud IAM security tool. "
    "Your ONLY job is to translate the user's natural-language query into the "
    "correct AdaPol CLI command. "
    "Never answer security questions yourself. "
    "Never invent file paths that the user didn't mention — use <placeholder> instead. "
    "Be deterministic and concise."
)

_COMMAND_CATALOGUE = """
Available AdaPol commands:

adapol analyze             --terraform <file> --events <file> --provider aws|azure|gcp
adapol demo
adapol generate-sample     --provider aws|azure|gcp --events <N>
adapol validate            <policy_file>
adapol report              <report_file> --format table|json|summary
adapol analyze-attack-paths --terraform <file> --events <file> --provider aws
adapol show-risk-report    --terraform <file> --events <file> --provider aws
adapol save-policy-snapshot --snapshot <file> --output <dir> --tag <label>
adapol compare-policy      --old <file> --new <file> --format table|json|both --show-all
adapol simulate-removal    --logs <file> --permission <perm>
adapol simulate-batch      --logs <file> --all-observed
adapol predict-failures    --logs <file> --all-observed --min-severity CRITICAL|HIGH|MEDIUM|LOW
adapol explain-policy      --policy <file>
adapol explain-attack-paths --attack-paths <file>
adapol explain-risk-report --report <file>
adapol explain-drift       --drift <file>
adapol explain-simulation  --simulation <file>
adapol ask                 "<free text>"
"""

_NL_PROMPT = """{system}

{catalogue}

User query: "{query}"

Translate this query into the best AdaPol CLI command.
Output exactly five sections separated by "|||":
1. The full CLI command string (use <placeholder> for unknown file paths)
2. Confidence score 0.0-1.0
3. One-sentence explanation of why you chose this command
4. Alternative commands as a pipe-separated list (or "none")
5. Required file flags as a pipe-separated list of flag names (e.g. --logs|--permission), or "none"
"""

_INTENT_MAP_PROMPT = """{system}

{catalogue}

User query: "{query}"

Which single CommandIntent best matches this query?
Reply with ONLY the intent value from this list:
analyze | demo | generate_sample | validate | report |
analyze_attack_paths | show_risk_report |
save_policy_snapshot | compare_policy |
simulate_removal | simulate_batch | predict_failures |
explain_policy | explain_attack_paths | explain_risk_report |
explain_drift | explain_simulation | unknown
"""


# ---------------------------------------------------------------------------
# NL Interface
# ---------------------------------------------------------------------------

class NLInterface:
    """
    Translates natural-language queries into AdaPol CLI command specifications.

    The output is always a ``ParsedCommand`` — never executed automatically.
    The caller decides whether and how to invoke the suggested command,
    ensuring humans remain in control of all security operations.

    Usage::

        nl = NLInterface()

        cmd = nl.parse("show me the highest risk services")
        print(cmd.cli_command)
        # → adapol show-risk-report --terraform <placeholder> --events <placeholder>

        cmd = nl.parse("explain this policy file policy.json")
        print(cmd.cli_command)
        # → adapol explain-policy --policy policy.json
    """

    _KEYWORD_RULES: List[Tuple[List[str], CommandIntent]] = [
        # ── Explain rules FIRST (most specific — must not be shadowed) ────
        (["explain polic", "what does this policy",
          "explain this policy", "policy file"],          CommandIntent.EXPLAIN_POLICY),
        (["explain attack", "describe attack",
          "explain attack paths", "narrate attack"],      CommandIntent.EXPLAIN_ATTACK_PATHS),
        (["explain risk", "summarise risk",
          "explain risk report", "executive summary",
          "show executive"],                              CommandIntent.EXPLAIN_RISK_REPORT),
        (["explain drift", "describe drift",
          "explain the drift"],                           CommandIntent.EXPLAIN_DRIFT),
        (["explain sim", "simulation result",
          "explain simulation"],                          CommandIntent.EXPLAIN_SIMULATION),
        # ── General operations ────────────────────────────────────────────
        (["demo", "example", "try it"],                  CommandIntent.DEMO),
        (["generate sample", "sample data", "test data"], CommandIntent.GENERATE_SAMPLE),
        (["validate", "check policy file"],               CommandIntent.VALIDATE),
        (["attack path", "attack vector", "escalation"],  CommandIntent.ANALYZE_ATTACK_PATHS),
        (["risk report", "risk score", "highest risk",
          "most dangerous", "risk level",
          "executive summary of risk"],                   CommandIntent.SHOW_RISK_REPORT),
        (["save snapshot", "save a snapshot",
          "store snapshot", "capture snapshot"],          CommandIntent.SAVE_POLICY_SNAPSHOT),
        (["compare polic", "policy change",
          "what changed", "old and new",
          "old snapshot", "new snapshot"],                CommandIntent.COMPARE_POLICY),
        (["simulate remov", "what if i remove",
          "can i remove", "safe to remove",
          "safely remove", "remove s3", "remove iam",
          "remove sts", "remove kms"],                    CommandIntent.SIMULATE_REMOVAL),
        (["simulate batch", "batch simul"],               CommandIntent.SIMULATE_BATCH),
        (["predict fail", "which function", "will break"],CommandIntent.PREDICT_FAILURES),
        (["analyze", "analyse", "generate polic"],        CommandIntent.ANALYZE),
    ]

    def __init__(self, api_key: Optional[str] = None) -> None:
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key
        self._model = None
        self._history: List[Dict[str, str]] = []
        logger.info("NLInterface created")

    # ── public API ────────────────────────────────────────────────────────

    def parse(self, query: str) -> ParsedCommand:
        """
        Parse a natural-language query into a structured ParsedCommand.

        Tries fast keyword matching first; falls back to Gemini if ambiguous.

        Args:
            query: Free-form user text, e.g. "show highest risk services"

        Returns:
            ParsedCommand with cli_command, intent, and confidence.
        """
        self._history.append({"role": "user", "content": query})
        query_lower = query.lower().strip()

        # Fast path: keyword heuristics (no API call)
        fast_intent = self._keyword_match(query_lower)
        if fast_intent != CommandIntent.UNKNOWN:
            cmd = self._build_command_from_intent(fast_intent, query, use_api=False)
            self._history.append({"role": "assistant", "content": cmd.cli_command})
            return cmd

        # Slow path: ask Gemini
        cmd = self._build_command_from_intent(
            CommandIntent.UNKNOWN, query, use_api=True
        )
        self._history.append({"role": "assistant", "content": cmd.cli_command})
        return cmd

    def ask(self, question: str) -> str:
        """
        Answer a free-form security question about AdaPol's capabilities.

        This does NOT trigger any CLI command. It explains what AdaPol can do
        and how to use it.

        Args:
            question: Any question about AdaPol.

        Returns:
            Plain-English answer from Gemini.
        """
        prompt = (
            f"{_NL_SYSTEM}\n\n"
            "The user is asking a general question about AdaPol or cloud security. "
            "Answer helpfully and concisely (≤ 100 words). "
            "If the question is about a specific operation, suggest the right "
            "AdaPol command.\n\n"
            f"Question: {question}"
        )
        return self._call_gemini(prompt).strip()

    def conversation_history(self) -> List[Dict[str, str]]:
        """Return the conversation history as a list of {role, content} dicts."""
        return list(self._history)

    def clear_history(self) -> None:
        """Reset conversation history."""
        self._history.clear()

    # ── intent → command builder ──────────────────────────────────────────

    def _build_command_from_intent(
        self,
        intent: CommandIntent,
        query: str,
        use_api: bool,
    ) -> ParsedCommand:
        """Build a ParsedCommand for a known or unknown intent."""
        if use_api or intent == CommandIntent.UNKNOWN:
            return self._gemini_parse(query)
        return self._heuristic_command(intent, query)

    def _heuristic_command(
        self, intent: CommandIntent, query: str
    ) -> ParsedCommand:
        """Build a best-effort ParsedCommand from keyword match alone."""
        # Extract any file paths mentioned in the query
        paths = re.findall(r'[\w./\\-]+\.(json|tf|csv|log)', query)

        templates: Dict[CommandIntent, Tuple[str, List[str]]] = {
            CommandIntent.DEMO: (
                "adapol demo", []),
            CommandIntent.GENERATE_SAMPLE: (
                "adapol generate-sample --provider aws --events 50", []),
            CommandIntent.VALIDATE: (
                f"adapol validate {paths[0] if paths else '<policy_file>'}",
                ["<policy_file>"]),
            CommandIntent.REPORT: (
                f"adapol report {paths[0] if paths else '<report_file>'} --format summary",
                ["<report_file>"]),
            CommandIntent.ANALYZE_ATTACK_PATHS: (
                "adapol analyze-attack-paths "
                f"--terraform {paths[0] if len(paths)>0 else '<terraform_file>'} "
                f"--events {paths[1] if len(paths)>1 else '<events_file>'} "
                "--provider aws --format table",
                ["--terraform", "--events"]),
            CommandIntent.SHOW_RISK_REPORT: (
                "adapol show-risk-report "
                f"--terraform {paths[0] if len(paths)>0 else '<terraform_file>'} "
                f"--events {paths[1] if len(paths)>1 else '<events_file>'} "
                "--provider aws --format table",
                ["--terraform", "--events"]),
            CommandIntent.SAVE_POLICY_SNAPSHOT: (
                f"adapol save-policy-snapshot "
                f"--snapshot {paths[0] if paths else '<snapshot_file>'} "
                "--output snapshots/",
                ["--snapshot"]),
            CommandIntent.COMPARE_POLICY: (
                f"adapol compare-policy "
                f"--old {paths[0] if len(paths)>0 else '<old_snapshot>'} "
                f"--new {paths[1] if len(paths)>1 else '<new_snapshot>'} "
                "--format table --show-all",
                ["--old", "--new"]),
            CommandIntent.SIMULATE_REMOVAL: (
                f"adapol simulate-removal "
                f"--logs {paths[0] if paths else '<logs_file>'} "
                "--permission <permission>",
                ["--logs", "--permission"]),
            CommandIntent.SIMULATE_BATCH: (
                f"adapol simulate-batch "
                f"--logs {paths[0] if paths else '<logs_file>'} "
                "--all-observed",
                ["--logs"]),
            CommandIntent.PREDICT_FAILURES: (
                f"adapol predict-failures "
                f"--logs {paths[0] if paths else '<logs_file>'} "
                "--all-observed --min-severity HIGH",
                ["--logs"]),
            CommandIntent.EXPLAIN_POLICY: (
                f"adapol explain-policy "
                f"--policy {paths[0] if paths else '<policy_file>'}",
                ["--policy"]),
            CommandIntent.EXPLAIN_ATTACK_PATHS: (
                f"adapol explain-attack-paths "
                f"--attack-paths {paths[0] if paths else '<attack_paths_file>'}",
                ["--attack-paths"]),
            CommandIntent.EXPLAIN_RISK_REPORT: (
                f"adapol explain-risk-report "
                f"--report {paths[0] if paths else '<report_file>'}",
                ["--report"]),
            CommandIntent.EXPLAIN_DRIFT: (
                f"adapol explain-drift "
                f"--drift {paths[0] if paths else '<drift_file>'}",
                ["--drift"]),
            CommandIntent.EXPLAIN_SIMULATION: (
                f"adapol explain-simulation "
                f"--simulation {paths[0] if paths else '<simulation_file>'}",
                ["--simulation"]),
            CommandIntent.ANALYZE: (
                "adapol analyze "
                f"--terraform {paths[0] if len(paths)>0 else '<terraform_file>'} "
                f"--events {paths[1] if len(paths)>1 else '<events_file>'} "
                "--provider aws",
                ["--terraform", "--events"]),
        }

        cli_cmd, requires = templates.get(
            intent,
            ("adapol --help", [])
        )

        return ParsedCommand(
            intent=intent,
            cli_command=cli_cmd,
            args=self._parse_args_from_cmd(cli_cmd),
            confidence=0.80,
            explanation=f"Matched intent '{intent.value}' via keyword heuristics.",
            alternatives=[],
            requires_files=requires,
            raw_query=query,
        )

    # ── Gemini-based parsing ──────────────────────────────────────────────

    def _gemini_parse(self, query: str) -> ParsedCommand:
        """Ask Gemini to translate the query into a CLI command."""
        prompt = _NL_PROMPT.format(
            system=_NL_SYSTEM,
            catalogue=_COMMAND_CATALOGUE,
            query=query,
        )
        raw = self._call_gemini(prompt)
        parts = [p.strip() for p in raw.split("|||")]
        while len(parts) < 5:
            parts.append("")

        cli_cmd   = parts[0].strip("`").strip()
        confidence = self._parse_confidence(parts[1])
        explanation = parts[2]
        alternatives = [a.strip() for a in parts[3].split("|") if a.strip() and a.strip() != "none"]
        requires     = [r.strip() for r in parts[4].split("|") if r.strip() and r.strip() != "none"]

        # Map CLI command back to intent
        intent = self._cli_to_intent(cli_cmd)

        return ParsedCommand(
            intent=intent,
            cli_command=cli_cmd,
            args=self._parse_args_from_cmd(cli_cmd),
            confidence=confidence,
            explanation=explanation,
            alternatives=alternatives,
            requires_files=requires,
            raw_query=query,
        )

    # ── helpers ───────────────────────────────────────────────────────────

    def _keyword_match(self, query_lower: str) -> CommandIntent:
        """Return the best CommandIntent from keyword rules, or UNKNOWN."""
        for keywords, intent in self._KEYWORD_RULES:
            if any(kw in query_lower for kw in keywords):
                return intent
        return CommandIntent.UNKNOWN

    @staticmethod
    def _parse_confidence(text: str) -> float:
        """Extract float confidence from Gemini output."""
        m = re.search(r"(\d+(?:\.\d+)?)", text)
        if m:
            val = float(m.group(1))
            return val if val <= 1.0 else val / 100.0
        return 0.7

    @staticmethod
    def _parse_args_from_cmd(cmd: str) -> Dict[str, str]:
        """Extract --flag value pairs from a CLI command string."""
        args: Dict[str, str] = {}
        tokens = cmd.split()
        i = 0
        while i < len(tokens):
            if tokens[i].startswith("--"):
                flag = tokens[i]
                val = tokens[i + 1] if i + 1 < len(tokens) and not tokens[i + 1].startswith("--") else "true"
                args[flag] = val
                i += 2
            else:
                i += 1
        return args

    @staticmethod
    def _cli_to_intent(cmd: str) -> CommandIntent:
        """Map a CLI command string back to a CommandIntent enum value."""
        mapping = {
            "analyze-attack-paths": CommandIntent.ANALYZE_ATTACK_PATHS,
            "show-risk-report":     CommandIntent.SHOW_RISK_REPORT,
            "save-policy-snapshot": CommandIntent.SAVE_POLICY_SNAPSHOT,
            "compare-policy":       CommandIntent.COMPARE_POLICY,
            "simulate-removal":     CommandIntent.SIMULATE_REMOVAL,
            "simulate-batch":       CommandIntent.SIMULATE_BATCH,
            "predict-failures":     CommandIntent.PREDICT_FAILURES,
            "explain-policy":       CommandIntent.EXPLAIN_POLICY,
            "explain-attack-paths": CommandIntent.EXPLAIN_ATTACK_PATHS,
            "explain-risk-report":  CommandIntent.EXPLAIN_RISK_REPORT,
            "explain-drift":        CommandIntent.EXPLAIN_DRIFT,
            "explain-simulation":   CommandIntent.EXPLAIN_SIMULATION,
            "analyze":              CommandIntent.ANALYZE,
            "demo":                 CommandIntent.DEMO,
            "validate":             CommandIntent.VALIDATE,
            "report":               CommandIntent.REPORT,
            "generate-sample":      CommandIntent.GENERATE_SAMPLE,
        }
        for key, intent in mapping.items():
            if key in cmd:
                return intent
        return CommandIntent.UNKNOWN

    def _call_gemini(self, prompt: str) -> str:
        """Send a prompt to Gemini and return the text response."""
        if self._model is None:
            try:
                import google.generativeai as genai  # type: ignore
                api_key = os.environ.get("GEMINI_API_KEY", "")
                if not api_key:
                    raise EnvironmentError("GEMINI_API_KEY not set")
                genai.configure(api_key=api_key)
                self._model = genai.GenerativeModel(
                    model_name="gemini-1.5-flash",
                    generation_config={
                        "temperature": 0.1,
                        "top_p": 0.8,
                        "max_output_tokens": 512,
                    },
                )
            except ImportError as exc:
                raise ImportError(
                    "google-generativeai not installed. "
                    "Run: pip install google-generativeai"
                ) from exc

        try:
            response = self._model.generate_content(prompt)
            return response.text.strip()
        except Exception as exc:
            logger.error("Gemini API error: %s", exc)
            raise RuntimeError(f"Gemini API call failed: {exc}") from exc
