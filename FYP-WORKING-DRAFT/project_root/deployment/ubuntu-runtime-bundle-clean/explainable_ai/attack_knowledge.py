"""
Attack context knowledge base for enhanced explanations.
Provides behavioral context, indicators, and impact analysis for threat types.
"""

ATTACK_CONTEXT = {
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
    }
}

def get_attack_context(attack_type):
    """Get knowledge base entry for an attack type."""
    return ATTACK_CONTEXT.get(attack_type, {
        "name": attack_type,
        "description": f"Attack of type {attack_type}",
        "how_it_works": "Unknown attack pattern detected",
        "indicators": [],
        "impact": "System compromise",
        "attacker_objective": "Unauthorized access or disruption",
        "response": ["Block source IP", "Investigate logs", "Isolate if necessary"]
    })
