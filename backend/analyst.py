"""AI Security Analyst: turns a flagged session into a plain-English incident summary.

Uses Claude when ANTHROPIC_API_KEY is set; otherwise (or on any API problem)
falls back to a built-in template, so the demo never depends on the internet.
"""
import json
import logging
import os

log = logging.getLogger("sentinel.analyst")

MODEL = os.getenv("SENTINEL_LLM_MODEL", "claude-opus-5")

SYSTEM_PROMPT = (
    "You are a senior SOC (security operations centre) analyst writing incident summaries "
    "for a security dashboard used by non-experts. Given one flagged login session, the "
    "employee's normal behaviour profile (their 'digital twin') and the detection signals, "
    "write 3-5 plain sentences with no markdown: what happened, how it differs from this "
    "employee's normal behaviour (quote the key numbers), the most likely attack type, and "
    "the recommended response. Only use facts present in the data."
)


def llm_enabled() -> bool:
    if os.getenv("SENTINEL_AI_ANALYST", "auto").lower() == "template":
        return False
    return bool(os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN"))


def _ask_claude(context: dict) -> str | None:
    import anthropic

    client = anthropic.Anthropic()
    try:
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=16000,
            output_config={"effort": "low"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": "Explain this flagged session:\n" + json.dumps(context, indent=2, default=str),
            }],
        )
    except anthropic.RateLimitError:
        log.warning("Claude rate limited; using template explanation")
        return None
    except anthropic.APIStatusError as exc:
        log.warning("Claude API error %s; using template explanation", exc.status_code)
        return None
    except anthropic.APIConnectionError:
        log.warning("Cannot reach Claude API; using template explanation")
        return None

    if response.stop_reason == "refusal":
        return None
    text = "".join(block.text for block in response.content if block.type == "text").strip()
    return text or None


def template_explanation(employee: dict, event: dict, verdict: dict) -> str:
    f = event["features"]
    who = employee["name"]
    when = f"{f['weekday']} at {f['time']}"
    if not verdict["reasons"]:
        return (f"{who}'s session on {when} from {f['city']} matches their digital twin: usual location, "
                f"known device and normal activity levels. Risk {verdict['risk']}/100, no action needed.")
    top = verdict["reasons"][:4]
    evidence = "; ".join(r["detail"] for r in top)
    threat = verdict.get("threat") or "anomalous behaviour"
    return (
        f"{who} ({employee['role']}) had a session on {when} from {f['city']}, {f['country']} that scored "
        f"{verdict['risk']}/100 ({verdict['tier']}). Compared with their digital twin: {evidence}. "
        f"This combination is most consistent with {threat[0].lower() + threat[1:]}. "
        f"Recommended response: {verdict['action']}"
        + (", then revoke active sessions and reset credentials." if verdict["tier"] == "BLOCK" else
           ", then verify the activity with the employee." if verdict["tier"] == "MFA" else ".")
    )


def explain(employee: dict, event: dict, twin: dict, verdict: dict) -> tuple[str, str]:
    """Return (explanation text, source) where source is 'claude' or 'template'."""
    if llm_enabled():
        context = {
            "employee": employee,
            "session": {k: v for k, v in event.items() if k not in ("features", "reasons")},
            "digital_twin": {k: v for k, v in twin.items() if k != "active_hours"},
            "verdict": verdict,
        }
        try:
            text = _ask_claude(context)
            if text:
                return text, "claude"
        except Exception:  # never let the analyst break the dashboard
            log.exception("AI analyst failed; using template explanation")
    return template_explanation(employee, event, verdict), "template"
