
COMMON_EDGE_FUNCTIONS = [
    "hello", "hello-world", "api", "webhook", "webhooks",
    "stripe-webhook", "stripe", "payment", "payments",
    "send-email", "email", "notify", "notification",
    "auth", "login", "register", "verify",
    "admin", "cron", "scheduled", "job",
    "upload", "process", "handler", "router",
    "graphql", "trpc", "rest",
]


def scan_edge_functions(client, label="anon"):
    findings = []
    accessible = []

    for fn in COMMON_EDGE_FUNCTIONS:
        status, data, _ = client.get(f"/functions/v1/{fn}")
        if status not in (404, 0):
            accessible.append((fn, status))

    if accessible:
        for fn, status in accessible:
            findings.append({
                "severity": "MEDIUM" if status == 200 else "INFO",
                "issue": f"[{label}] Edge function '/{fn}' responded with status {status}",
            })
        if any(s == 200 for _, s in accessible):
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] {sum(1 for _, s in accessible if s == 200)} edge function(s) are callable without authentication — review each for sensitive logic or data access",
            })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No common edge function names responded (none deployed or all require auth)",
        })

    return findings


def scan_realtime(client, label="anon"):
    findings = []

    status, data, headers = client.get("/realtime/v1/api")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "issue": f"[{label}] Realtime API info endpoint is accessible — broadcasts may be open to unauthenticated listeners",
        })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Realtime API returned {status}",
        })

    return findings


def scan_postgrest_info(client, label="anon"):
    findings = []

    status, data, _ = client.get("/rest/v1/")
    if status == 200 and isinstance(data, dict):
        info = data.get("info", {})
        version = info.get("version", "")
        title = info.get("title", "")
        if version:
            findings.append({
                "severity": "LOW",
                "issue": f"[{label}] PostgREST version disclosed: '{version}' — check for known CVEs for this version",
            })
        if title:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] API title: '{title}'",
            })

        description = info.get("description", "")
        if description:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] API description: '{description}'",
            })

    return findings
