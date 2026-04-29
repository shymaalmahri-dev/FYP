"""
Attack context knowledge base for enhanced explanations.
Provides behavioral context, indicators, and impact analysis for threat types.
"""

ATTACK_CONTEXT = {
    "Gray_Zone_Review": {
        "name": "Gray-Zone Review",
        "description": "Traffic that is suspicious enough for analyst review but not strong enough for automatic containment",
        "how_it_works": "The model leans toward a malicious class, but the confidence gap versus benign or competing classes is too small to justify immediate blocking",
        "indicators": ["borderline class probabilities", "low confidence gap", "conflicting features", "no corroborating signature hit"],
        "impact": "Potential precursor activity or model uncertainty requiring validation",
        "attacker_objective": "Unknown until corroborated; could be reconnaissance, staging, or benign traffic resembling attack telemetry",
        "response": ["Review packet captures", "Check host and service logs", "Escalate only if corroborating evidence confirms malicious intent"]
    },
    "Normal_Traffic": {
        "name": "Sampled Normal Traffic",
        "description": "Benign traffic retained for expert validation of the model's normal classification behavior",
        "how_it_works": "The model classified the flow as normal or near-normal and the event was sampled for analyst review rather than containment",
        "indicators": ["benign protocol behavior", "absence of signature hits", "stable traffic features", "normal service access patterns"],
        "impact": "No immediate security impact expected; used to validate false positive performance",
        "attacker_objective": "None observed",
        "response": ["Observe only", "Use as validation sample", "Compare with malicious detections to assess model drift"]
    },
    "SYN_Flood": {
        "name": "SYN Flood (DoS Attack)",
        "description": "Volumetric attack attempting to exhaust server resources by overwhelming with TCP SYN packets",
        "how_it_works": "Attacker sends large volumes of SYN packets with spoofed source IPs, exhausting server connection queue and preventing legitimate connections",
        "indicators": ["high packet rate", "small packet sizes", "TCP SYN flags", "abnormal window size", "low TTL variance"],
        "impact": "Service availability - target becomes unresponsive to legitimate users",
        "attacker_objective": "Deny service availability, cause downtime, disrupt operations",
        "response": ["Rate limit incoming SYN packets", "Enable SYN cookies", "Block source IP", "Contact ISP for upstream filtering"]
    },
    "SQL_Injection": {
        "name": "SQL Injection Attack",
        "description": "Attempt to manipulate database queries by injecting malicious SQL code through user input",
        "how_it_works": "Attacker inserts SQL keywords and syntax into input fields to alter query logic, bypass authentication, or extract/modify data",
        "indicators": ["SQL keywords in payload", "encoded strings", "special characters", "quote marks", "comment sequences"],
        "impact": "Data confidentiality & integrity - unauthorized access to sensitive information, data modification/deletion",
        "attacker_objective": "Steal data, modify records, bypass authentication, escalate privileges",
        "response": ["Block source IP", "Isolate database", "Check logs for unauthorized access", "Apply WAF rules", "Patch vulnerability immediately"]
    },
    "Directory_Traversal": {
        "name": "Directory Traversal Attack",
        "description": "Attempt to access files and directories outside the intended root directory",
        "how_it_works": "Attacker uses path traversal sequences (../, ..\\\\ etc.) to navigate filesystem and access sensitive files like passwords, configs",
        "indicators": ["path traversal sequences", "encoded slashes", "double encoding", "null bytes", "relative paths"],
        "impact": "Confidentiality - unauthorized access to sensitive configuration files, source code, or credentials",
        "attacker_objective": "Access sensitive files, extract credentials, discover system architecture",
        "response": ["Block source IP", "Review access logs", "Verify web server configuration", "Implement input validation", "Patch application"]
    },
    "XSS_Injection": {
        "name": "Cross-Site Scripting (XSS) Attack",
        "description": "Injection of malicious JavaScript code that executes in victim browsers to steal sessions or perform actions",
        "how_it_works": "Attacker injects scripts into web pages that execute in user browsers, stealing cookies, sessions, or performing unauthorized actions",
        "indicators": ["JavaScript tags", "event handlers", "script URLs", "HTML entities", "encoded payloads"],
        "impact": "Confidentiality & integrity - session hijacking, credential theft, malware distribution, defacement",
        "attacker_objective": "Steal user sessions, capture credentials, distribute malware, deface content",
        "response": ["Block source IP", "Clear affected user sessions", "Review application logs", "Implement content security policy", "Sanitize inputs"]
    },
    "Command_Injection": {
        "name": "Command Injection Attack",
        "description": "Injection of arbitrary system commands through user input to execute unauthorized operations",
        "how_it_works": "Attacker uses shell metacharacters (|, ;, &, `, $) to break out of intended command and execute malicious system commands",
        "indicators": ["shell metacharacters", "command separators", "pipe symbols", "backticks", "dollar signs"],
        "impact": "Integrity & availability - unauthorized command execution, system compromise, data exfiltration",
        "attacker_objective": "Execute system commands, create backdoors, steal data, pivot to other systems",
        "response": ["Block source IP immediately", "Isolate affected system", "Check command history", "Review for backdoors", "Full system audit"]
    },
    "Port_Scanning": {
        "name": "Port Scanning",
        "description": "Reconnaissance activity probing multiple ports to discover exposed services",
        "how_it_works": "Attacker sends connection attempts across a range of ports to map reachable services and find potential attack surfaces",
        "indicators": ["multiple destination ports", "short inter-arrival times", "scan-like SYN behavior", "high port entropy"],
        "impact": "Exposure discovery and follow-on attack planning",
        "attacker_objective": "Identify reachable services and weak targets for later exploitation",
        "response": ["Block or rate-limit the source", "Review exposed services", "Correlate with follow-on activity"]
    },
    "Stealth_Horizontal_Port_Scan": {
        "name": "Stealth Horizontal Port Scan",
        "description": "Low-and-slow scanning behavior targeting multiple ports while attempting to avoid volumetric thresholds",
        "how_it_works": "Attacker spreads connection attempts across ports over time to discover services without triggering simple rate-based alarms",
        "indicators": ["moderate packet rate", "growing unique ports hit", "elevated port entropy", "limited payload data"],
        "impact": "Reconnaissance that can precede targeted exploitation",
        "attacker_objective": "Map available services while minimizing detection",
        "response": ["Review the source host", "Block if unauthorized", "Inspect adjacent alerts for follow-on exploitation"]
    }
}

def get_attack_context(attack_type):
    """Get knowledge base entry for an attack type."""
    if attack_type in ATTACK_CONTEXT:
        return ATTACK_CONTEXT[attack_type]

    if attack_type.startswith("Brute_Force_Attempt_on_Port_"):
        port = attack_type.split("_")[-1]
        return {
            "name": f"Brute Force Attempt on Port {port}",
            "description": "Repeated low-payload connection attempts against the same service suggest credential guessing or service hammering",
            "how_it_works": "Attacker repeatedly contacts the same service in a tight time window, attempting to elicit authentication or connection responses without large payload transfers",
            "indicators": ["repeated connections", "low byte volume", "concentrated destination port", "behavioral threshold exceeded"],
            "impact": "Credential compromise risk or service degradation",
            "attacker_objective": f"Gain access to the service listening on port {port} or exhaust it through repeated attempts",
            "response": ["Keep the source blocked", "Review authentication or service logs", "Check for successful access attempts", "Harden the targeted service"]
        }

    if attack_type.startswith("High_Port_Ephemeral_Sweep"):
        return {
            "name": "High-Port Ephemeral Sweep",
            "description": "Broad probing of high or ephemeral ports suggests service discovery beyond common well-known ports",
            "how_it_works": "Attacker touches many high-numbered ports to locate internal services, agent listeners, or temporary application ports",
            "indicators": ["many distinct high ports", "high port entropy", "scan-like connection bursts"],
            "impact": "Reconnaissance of less obvious services that may be weakly protected",
            "attacker_objective": "Identify hidden or transient services for exploitation",
            "response": ["Contain the source", "Review high-port listeners on the target", "Correlate with other reconnaissance events"]
        }

    return ATTACK_CONTEXT.get(attack_type, {
        "name": attack_type,
        "description": f"Attack of type {attack_type}",
        "how_it_works": "Unknown attack pattern detected",
        "indicators": [],
        "impact": "System compromise",
        "attacker_objective": "Unauthorized access or disruption",
        "response": ["Block source IP", "Investigate logs", "Isolate if necessary"]
    })
