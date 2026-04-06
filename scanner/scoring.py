from typing import List, Dict, Any, Tuple, Optional

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH":     15,
    "MEDIUM":    5,
    "LOW":       1,
    "INFO":      0,
}

MAX_SCORE = 100

RISK_BANDS = [
    (80, "CRITICAL RISK",  "\033[91m", "Immediate action required. Sensitive data is likely exposed right now."),
    (50, "HIGH RISK",      "\033[31m", "Serious vulnerabilities present. Remediate before going to production."),
    (25, "MEDIUM RISK",    "\033[93m", "Moderate issues found. Review and address during next sprint."),
    (10, "LOW RISK",       "\033[94m", "Minor issues. Good baseline security with some hardening recommended."),
    (0,  "MINIMAL RISK",   "\033[92m", "No significant issues detected. Continue monitoring."),
]

REMEDIATION = {
    "rls_disabled": (
        "Row Level Security is not enforced",
        "Enable RLS on every table: `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;` then add policies.",
    ),
    "public_bucket": (
        "Storage bucket is publicly accessible",
        "Set bucket to private in Supabase Dashboard → Storage → Bucket settings.",
    ),
    "long_lived_jwt": (
        "JWT token has a very long expiry window",
        "Rotate your API keys in Supabase Dashboard → Settings → API. Generate new keys with shorter lifetimes.",
    ),
    "open_signup": (
        "Open signup allows anyone to register",
        "Disable in Supabase Dashboard → Authentication → Providers → Email → Disable sign ups.",
    ),
    "email_enumeration": (
        "Email enumeration via password reset",
        "Enable 'Protect against email enumeration' in Auth → Email settings.",
    ),
    "cors_wildcard": (
        "CORS wildcard allows any origin",
        "Restrict allowed origins in Supabase Dashboard → Settings → API → CORS.",
    ),
    "graphql_introspection": (
        "GraphQL introspection leaks schema",
        "Disable introspection in production: set `PGRST_DB_ANON_ROLE` restrictions or block introspection queries via RLS.",
    ),
    "sensitive_columns": (
        "Tables contain sensitive column names readable by anon",
        "Apply RLS policies to restrict access: `CREATE POLICY ... USING (auth.uid() = user_id);`",
    ),
    "service_role_exposed": (
        "Service role key is in use",
        "Never include the service_role key in client-side or frontend code. Use it only in server-side environments.",
    ),
    "missing_hsts": (
        "HSTS header is absent",
        "Configure your reverse proxy or CDN to send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    ),
}

def normalize_severity(severity: str) -> str:
    severity_upper = severity.upper()
    for valid in SEVERITY_WEIGHTS.keys():
        if valid in severity_upper:
            return valid
    return "INFO"

def calculate_score(findings: Optional[List[Dict[str, Any]]]) -> int:
    if not findings:
        return 0
    
    raw = 0
    for f in findings:
        severity = f.get("severity", "INFO")
        normalized = normalize_severity(severity)
        weight = SEVERITY_WEIGHTS.get(normalized, 0)
        raw += weight
    
    return min(raw, MAX_SCORE)

def get_risk_band(score: int) -> Tuple[str, str, str]:
    for threshold, label, color, description in RISK_BANDS:
        if score >= threshold:
            return label, color, description
    return RISK_BANDS[-1][1], RISK_BANDS[-1][2], RISK_BANDS[-1][3]

def generate_remediation(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    if not findings:
        return []
    
    hints = []
    seen = set()
    
    finding_types = []
    for f in findings:
        finding_type = f.get("type", "").lower()
        issue = f.get("issue", "").lower()
        finding_types.append(finding_type)
        
        if finding_type and finding_type not in seen:
            seen.add(finding_type)
    
    for finding in findings:
        issue_text = finding.get("issue", "").lower()
        finding_type = finding.get("type", "").lower()
        
        checks = {
            "rls_disabled": "rls disabled" in issue_text or "row level security" in issue_text or "readable by anonymous" in issue_text,
            "public_bucket": "public" in issue_text and "bucket" in issue_text,
            "long_lived_jwt": "years away" in issue_text or "expiry" in issue_text and "long" in issue_text,
            "open_signup": "open signup" in issue_text or "sign up" in issue_text and "open" in issue_text,
            "email_enumeration": "email enumeration" in issue_text or "email" in issue_text and "enumeration" in issue_text,
            "cors_wildcard": "cors" in issue_text and ("wildcard" in issue_text or "open" in issue_text),
            "graphql_introspection": "graphql" in issue_text and "introspection" in issue_text,
            "sensitive_columns": "sensitive" in issue_text and "column" in issue_text,
            "service_role_exposed": "service_role" in issue_text or "service role" in issue_text,
            "missing_hsts": "hsts" in issue_text and ("missing" in issue_text or "not set" in issue_text),
        }
        
        for key, triggered in checks.items():
            if triggered and key not in seen:
                seen.add(key)
                if key in REMEDIATION:
                    problem, fix = REMEDIATION[key]
                    hints.append({"problem": problem, "fix": fix})
    
    if not hints and findings:
        default_hint = {
            "problem": "Security findings detected",
            "fix": "Review all findings and implement appropriate security controls based on severity."
        }
        hints.append(default_hint)
    
    return hints

def print_score_card(findings: List[Dict[str, Any]]) -> None:
    score = calculate_score(findings)
    label, color, description = get_risk_band(score)
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"

    bar_filled = int((score / MAX_SCORE) * 40) if MAX_SCORE > 0 else 0
    bar = f"{color}{'█' * bar_filled}{DIM}{'░' * (40 - bar_filled)}{RESET}"

    print(f"\n{'─' * 70}")
    print(f"\n  {BOLD}Risk Score{RESET}\n")
    print(f"  [{bar}] {color}{BOLD}{score}/{MAX_SCORE}{RESET}")
    print(f"\n  {color}{BOLD}{label}{RESET}")
    print(f"  {DIM}{description}{RESET}\n")

    hints = generate_remediation(findings)
    if hints:
        print(f"  {BOLD}Remediation Priorities{RESET}\n")
        for i, hint in enumerate(hints, 1):
            print(f"  {i}. {BOLD}{hint['problem']}{RESET}")
            print(f"     {DIM}{hint['fix']}{RESET}\n")

def score_to_dict(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    score = calculate_score(findings)
    label, _, description = get_risk_band(score)
    return {
        "score": score,
        "max": MAX_SCORE,
        "label": label,
        "description": description,
        "remediation": generate_remediation(findings),
    }
