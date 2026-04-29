import json
import os
import ollama
from attack_knowledge import get_attack_context

print("[GenAI] Incident report generator starting...")

BASE_DIR = os.path.dirname(__file__)

EXPLANATION_FILE = os.path.join(BASE_DIR, "reports", "explanations.json")
REPORT_FILE = os.path.join(BASE_DIR, "genai_reports", "incident_reports.json")


def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def build_prompt(attack_type, attacker_ip, features, verbosity="brief"):
    """
    Build a prompt for Ollama with attack context and configurable verbosity.
    
    verbosity: "brief" (2-3 sentences), "detailed" (5-7 sentences), "forensic" (full analysis)
    """
    feature_text = ""
    for f in features:
        feature_text += f"- {f['feature']} (impact {round(f['impact'],3)})\n"
    
    context = get_attack_context(attack_type)
    
    if verbosity == "brief":
        prompt = f"""
You are a cybersecurity SOC analyst.

Attack Type: {attack_type}
Description: {context['description']}
Attacker IP: {attacker_ip}

Key indicators identified by the AI model:
{feature_text}

Write a brief 2-3 sentence explanation of why this attack was detected
and what behavior indicates malicious activity. Focus on the features and their significance.
"""
    
    elif verbosity == "detailed":
        prompt = f"""
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
"""
    
    else:  # forensic
        response_text = ', '.join(context['response']) if context.get('response') else "Monitor and isolate"
        prompt = f"""
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
"""
    
    return prompt


def generate_report(prompt):
    """Generate a report using Ollama."""
    response = ollama.chat(
        model="llama3",
        messages=[{"role": "user", "content": prompt}]
    )
    return response["message"]["content"]


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

        prompt = build_prompt(
            exp["attack_type"],
            exp["attacker_ip"],
            exp["top_features"],
            verbosity="detailed"
        )

        report_text = generate_report(prompt)

        incident = {
            "timestamp": exp["timestamp"],
            "attacker_ip": exp["attacker_ip"],
            "attack_type": exp["attack_type"],
            "report": report_text
        }

        reports.append(incident)

        # ✅ Save after each report to avoid data loss
        save_json(REPORT_FILE, reports)
        print(f"[GenAI] Saved report for {exp['attacker_ip']}")

    print(f"[GenAI] Generated {len(new_explanations)} reports in total.")


if __name__ == "__main__":
    process_explanations()
