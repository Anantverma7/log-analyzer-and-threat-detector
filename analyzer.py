import re
THREAT_PATTERNS = {
    'SQL_INJECTION': r"(UNION SELECT|OR 1=1|--)",
    'BRUTE_FORCE': r"(401 Unauthorized|Login Failed|Invalid Password)",
    'DDOS_ATTACK': r"(503 Service Unavailable|Too Many Requests)"
}

def analyze_log(file_stream):
    threats_found = []
    for line in file_stream:
        line = line.decode('utf-8')
        for threat_name, pattern in THREAT_PATTERNS.items():
            if re.search(pattern, line, re.IGNORECASE):
                threats_found.append({
                    'type': threat_name,
                    'content': line
                })
    return threats_found
