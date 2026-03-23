
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


def calculate_score(findings):
    raw = sum(SEVERITY_WEIGHTS.get(f.get("severity", "INFO"), 0) for f in findings)
    score = min(raw, MAX_SCORE)
    return score


def get_risk_band(score):
    for threshold, label, color, description in RISK_BANDS:
        if score >= threshold:
            return label, color, description
    return RISK_BANDS[-1][1], RISK_BANDS[-1][2], RISK_BANDS[-1][3]


def generate_remediation(findings):
    hints = []
    seen = set()
    issue_text = " ".join(f.get("issue", "").lower() for f in findings)

    checks = {
        "rls_disabled":           "row(s) readable by anonymous" in issue_text or "rls disabled" in issue_text,
        "public_bucket":          "is public" in issue_text,
        "long_lived_jwt":         "years away" in issue_text,
        "open_signup":            "open signup" in issue_text,
        "email_enumeration":      "email enumeration" in issue_text,
        "cors_wildcard":          "cors is open" in issue_text,
        "graphql_introspection":  "introspection is enabled" in issue_text,
        "sensitive_columns":      "sensitive-looking columns" in issue_text,
        "service_role_exposed":   "service_role" in issue_text and "bypasses row level security" in issue_text,
        "missing_hsts":           "hsts not set" in issue_text,
    }

    for key, triggered in checks.items():
        if triggered and key not in seen:
            seen.add(key)
            problem, fix = REMEDIATION[key]
            hints.append({"problem": problem, "fix": fix})

    return hints


def print_score_card(findings):
    score = calculate_score(findings)
    label, color, description = get_risk_band(score)
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"

    bar_filled = int((score / MAX_SCORE) * 40)
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


def score_to_dict(findings):
    score = calculate_score(findings)
    label, _, description = get_risk_band(score)
    return {
        "score": score,
        "max": MAX_SCORE,
        "label": label,
        "description": description,
        "remediation": generate_remediation(findings),
    }
