"""
AI explanation module for THREATGUARD.

Uses the Groq API to generate plain-language explanations for findings
that have already been detected and classified by deterministic rules.

IMPORTANT SAFETY CONSTRAINTS
─────────────────────────────
• The AI explains findings only. It does NOT:
  - Discover new vulnerabilities
  - Change severity or confidence levels
  - Fabricate evidence
  - Add or remove recommendations

• If GROQ_API_KEY is not configured, the module returns a graceful fallback
  so the application continues to work without AI features.
"""
from __future__ import annotations

import os

try:
    from groq import Groq
    _GROQ_AVAILABLE = True
except ImportError:
    _GROQ_AVAILABLE = False

# ── Supported Groq models (in preference order) ───────────────────────────────
_PREFERRED_MODELS = [
    "llama3-8b-8192",
    "llama3-70b-8192",
    "mixtral-8x7b-32768",
    "gemma-7b-it",
]

_SYSTEM_PROMPT = """You are a cybersecurity educator helping a small website owner understand a security or privacy finding detected by an automated scanner.

Your role is strictly to EXPLAIN the finding provided to you. You must NOT:
- Invent new vulnerabilities
- Change the severity or confidence level
- Add findings that were not detected by the scanner
- Make speculative claims about the specific site

Respond in four clearly labelled sections:
1. What does this mean? (simple explanation, 2-3 sentences)
2. Why is it dangerous? (practical risk, 2-3 sentences)
3. How can it affect visitors? (user-facing impact, 2-3 sentences)
4. How can it be fixed? (actionable steps, based only on the recommendation provided)

Use simple language suitable for a non-technical website owner. Keep each section concise."""


def get_groq_client() -> "Groq | None":
    """Return a Groq client if API key is available."""
    if not _GROQ_AVAILABLE:
        return None
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key or api_key == "your_groq_api_key_here":
        return None
    try:
        return Groq(api_key=api_key)
    except Exception:
        return None


def is_ai_available() -> bool:
    """Check whether AI explanation is available."""
    return get_groq_client() is not None


def explain_finding(finding: dict, client=None) -> str:
    """
    Generate an AI explanation for a single finding.

    Parameters
    ----------
    finding : dict
        Must contain finding_name, severity, confidence, evidence,
        impact, recommendation.
    client : Groq | None
        Optionally pass a pre-created client for efficiency.

    Returns
    -------
    str  – AI-generated explanation, or a fallback message.
    """
    if client is None:
        client = get_groq_client()

    if client is None:
        return _fallback_explanation(finding)

    prompt = _build_prompt(finding)

    for model in _PREFERRED_MODELS:
        try:
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.4,
                max_tokens=600,
            )
            return completion.choices[0].message.content.strip()
        except Exception as exc:
            last_error = str(exc)
            continue

    return _fallback_explanation(finding, error=last_error)


def explain_all_findings(findings: list[dict]) -> dict[int, str]:
    """
    Generate AI explanations for a list of findings.

    Returns
    -------
    dict mapping finding index → explanation string
    """
    client = get_groq_client()
    results: dict[int, str] = {}
    for i, finding in enumerate(findings):
        results[i] = explain_finding(finding, client=client)
    return results


def _build_prompt(finding: dict) -> str:
    return f"""Please explain the following security/privacy finding detected on a website:

Finding Name: {finding.get('finding_name', 'Unknown')}
Category: {finding.get('category', 'security')}
Severity: {finding.get('severity', 'Unknown')}
Confidence: {finding.get('confidence', 'Unknown')}

Technical Evidence:
{finding.get('evidence', 'No evidence available.')}

Business Impact:
{finding.get('impact', 'No impact information.')}

Recommended Fix:
{finding.get('recommendation', 'No recommendation available.')}

Please explain this finding in the four sections described in your instructions."""


def _fallback_explanation(finding: dict, error: str = "") -> str:
    """Return a structured fallback when AI is unavailable."""
    name = finding.get("finding_name", "this finding")
    impact = finding.get("impact", "")
    rec = finding.get("recommendation", "")
    severity = finding.get("severity", "")

    lines = [
        "**AI explanation not available** (Groq API key not configured or quota exceeded).",
        "",
        f"**1. What does this mean?**  \n{name} was detected on the target website.",
        "",
        f"**2. Why is it dangerous?**  \nSeverity: {severity}. {impact[:300] if impact else 'See the impact column for details.'}",
        "",
        "**3. How can it affect visitors?**  \nSee the Impact column in the findings table for visitor-facing risks.",
        "",
        f"**4. How can it be fixed?**  \n{rec[:400] if rec else 'See the Recommendation column for fix details.'}",
    ]
    if error:
        lines.append(f"\n*API error: {error[:100]}*")

    return "\n".join(lines)
