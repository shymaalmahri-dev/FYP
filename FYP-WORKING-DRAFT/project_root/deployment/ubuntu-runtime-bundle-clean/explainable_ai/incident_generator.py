import argparse
import json
import os

from attack_knowledge import get_attack_context

try:
    import ollama
except Exception:
    ollama = None


BASE_DIR = os.path.dirname(__file__)
EXPLANATION_FILE = os.path.join(BASE_DIR, "reports", "explanations.json")
REPORT_FILE = os.path.join(BASE_DIR, "genai_reports", "incident_reports.json")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")


def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def normalize_features(features):
    normalized = []
    for item in features or []:
        if not isinstance(item, dict):
            continue

        feature_name = item.get("feature") or item.get("name")
        if not feature_name:
            continue

        impact_value = item.get("impact", item.get("importance", 0))
        try:
            impact_value = float(impact_value)
        except (TypeError, ValueError):
            impact_value = 0.0

        normalized.append(
            {
                "feature": feature_name,
                "impact": impact_value,
                "value": item.get("value"),
            }
        )

    return normalized


def build_feature_text(features):
    normalized = normalize_features(features)
    if not normalized:
        return "- No SHAP features were available; rely on attack context and network metadata.\n"

    return "".join(
        f"- {item['feature']} (impact {round(item['impact'], 3)})\n"
        for item in normalized
    )


def build_prompt(attack_type, attacker_ip, features, verbosity="brief"):
    """
    Build a prompt for Ollama with attack context and configurable verbosity.

    verbosity: "brief" (2-3 sentences), "detailed" (5-7 sentences), "forensic" (full analysis)
    """
    context = get_attack_context(attack_type)
    feature_text = build_feature_text(features)

    if verbosity == "brief":
        return f"""
You are a cybersecurity SOC analyst.

Attack Type: {attack_type}
Description: {context['description']}
Attacker IP: {attacker_ip}

Key indicators identified by the AI model:
{feature_text}

Write a brief 2-3 sentence explanation of why this attack was detected
and what behavior indicates malicious activity. Focus on the features and their significance.
""".strip()

    if verbosity == "detailed":
        return f"""
You are a cybersecurity SOC analyst. Provide a DETAILED professional analysis.

Attack Type: {attack_type} - {context['name']}
Attacker IP: {attacker_ip}

How This Attack Works:
{context['how_it_works']}

Expected Indicators:
{', '.join(context['indicators'])}

Key indicators identified by the AI model:
{feature_text}

Write a comprehensive 5-7 sentence incident report that includes:
1. Why was this attack detected (behavioral analysis)?
2. What is the attacker's likely objective?
3. What would be the impact if this attack succeeded?
4. Any recommended immediate actions?

Be specific and technical in your analysis.
""".strip()

    response_text = ", ".join(context["response"]) if context.get("response") else "Monitor and isolate"
    return f"""
You are a senior cybersecurity forensics analyst. Provide COMPREHENSIVE forensic analysis.

Attack Type: {attack_type} - {context['name']}
Attacker IP: {attacker_ip}

Attack Background:
{context['description']}

Attack Methodology:
{context['how_it_works']}

Expected Indicators:
{', '.join(context['indicators'])}

Impact Category: {context['impact']}
Attacker Objective: {context['attacker_objective']}

Model-Detected Key Indicators:
{feature_text}

Recommended Response Actions:
{response_text}

Provide a DETAILED forensic analysis (10-15 sentences) including:
1. Complete technical breakdown of the attack vector
2. Why each detected indicator is significant
3. Likely attacker capabilities and sophistication level
4. Potential lateral movement paths
5. Immediate containment recommendations
6. Evidence preservation requirements
7. Long-term mitigation strategies

This analysis should be suitable for executive briefing and incident response teams.
""".strip()


def build_fallback_report(attack_type, attacker_ip, features, verbosity="detailed"):
    context = get_attack_context(attack_type)
    normalized = normalize_features(features)
    top_features = ", ".join(
        f"{item['feature']} ({round(item['impact'], 3)})"
        for item in normalized[:4]
    )

    if verbosity == "brief":
        if top_features:
            return (
                f"{attack_type} activity from {attacker_ip} was flagged because the model observed indicators such as "
                f"{top_features}. This pattern aligns with {context['description'].lower()}."
            )
        return (
            f"{attack_type} activity from {attacker_ip} was flagged based on malicious traffic behavior. "
            f"It aligns with {context['description'].lower()}."
        )

    if verbosity == "forensic":
        return (
            f"FORENSIC ANALYSIS - {context['name']}\n\n"
            f"Source IP: {attacker_ip}\n"
            f"Attack Summary: {context['description']}\n"
            f"Methodology: {context['how_it_works']}\n"
            f"Top Indicators: {top_features or 'No SHAP indicators available; use attack context and packet metadata.'}\n"
            f"Likely Objective: {context['attacker_objective']}\n"
            f"Impact: {context['impact']}\n"
            f"Recommended Response: {', '.join(context['response'])}"
        )

    return (
        f"{context['name']} activity was detected from {attacker_ip}. "
        f"The behavior matches this attack profile: {context['how_it_works']} "
        f"{'Top indicators included ' + top_features + '. ' if top_features else ''}"
        f"Likely impact: {context['impact']}. Recommended response: {', '.join(context['response'])}."
    )


def generate_report(prompt, attack_type=None, attacker_ip=None, features=None, verbosity="detailed"):
    """Generate a report using Ollama, or fall back to a deterministic summary."""
    if ollama is None:
        return build_fallback_report(attack_type or "Unknown", attacker_ip or "unknown", features, verbosity)

    try:
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
        )
        content = response.get("message", {}).get("content", "").strip()
        if content:
            return content
    except Exception as exc:
        print(f"[GenAI] Ollama generation failed: {exc}")

    return build_fallback_report(attack_type or "Unknown", attacker_ip or "unknown", features, verbosity)


def generate_on_demand_analysis(attack_type, attacker_ip, features, verbosity="detailed"):
    prompt = build_prompt(attack_type, attacker_ip, features, verbosity)
    analysis = generate_report(prompt, attack_type, attacker_ip, features, verbosity)
    return {"analysis": analysis}


def process_explanations():
    explanations = load_json(EXPLANATION_FILE)
    reports = load_json(REPORT_FILE)

    processed = len(reports)
    new_explanations = explanations[processed:]

    if not new_explanations:
        print("[GenAI] No new explanations.")
        return

    for exp in new_explanations:
        print(f"[GenAI] Generating report for {exp['attacker_ip']}")
        features = normalize_features(exp.get("top_features", []))
        prompt = build_prompt(
            exp["attack_type"],
            exp["attacker_ip"],
            features,
            verbosity="detailed",
        )
        report_text = generate_report(
            prompt,
            exp["attack_type"],
            exp["attacker_ip"],
            features,
            "detailed",
        )

        incident = {
            "timestamp": exp["timestamp"],
            "attacker_ip": exp["attacker_ip"],
            "attack_type": exp["attack_type"],
            "report": report_text,
        }

        reports.append(incident)
        save_json(REPORT_FILE, reports)
        print(f"[GenAI] Saved report for {exp['attacker_ip']}")

    print(f"[GenAI] Generated {len(new_explanations)} reports in total.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Incident report generator")
    parser.add_argument("--attack-type", type=str, help="Attack type for analysis")
    parser.add_argument("--attacker-ip", type=str, help="Source IP of the alert")
    parser.add_argument(
        "--features",
        type=str,
        default="[]",
        help="JSON string of features for the alert",
    )
    parser.add_argument(
        "--verbosity",
        type=str,
        choices=["brief", "detailed", "forensic"],
        default="detailed",
        help="Verbosity level for analysis",
    )

    args = parser.parse_args()

    if args.attack_type and args.attacker_ip:
        try:
            features = json.loads(args.features or "[]")
        except json.JSONDecodeError:
            features = []

        analysis = generate_on_demand_analysis(
            args.attack_type,
            args.attacker_ip,
            features,
            args.verbosity,
        )
        print(json.dumps(analysis))
    else:
        process_explanations()
