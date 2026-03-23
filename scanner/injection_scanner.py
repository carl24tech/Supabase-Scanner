import urllib.parse


POSTGREST_ORDER_INJECTIONS = [
    "id;select 1",
    "id asc nulls first,(select 1)",
    "(select 1 from pg_sleep(0))",
]

POSTGREST_FILTER_INJECTIONS = [
    "eq.1' or '1'='1",
    "eq.1%27%20or%20%271%27%3D%271",
    "like.*",
    "ilike.*",
    "gt.-999999",
]

POSTGREST_SELECT_INJECTIONS = [
    "*,version()",
    "*,(select version())",
    "id,pg_sleep(0)",
]


def _probe_injection(client, table, param_name, payloads, extra_params=None):
    findings = []
    for payload in payloads:
        params = {param_name: payload, "limit": "1"}
        if extra_params:
            params.update(extra_params)
        status, data, _ = client.get(f"/rest/v1/{table}", params=params)
        if status == 200 and isinstance(data, list) and len(data) > 0:
            findings.append({
                "severity": "HIGH",
                "issue": f"Table '{table}': injection probe '{param_name}={payload}' returned data — possible filter bypass",
                "payload": payload,
            })
        elif status == 500:
            findings.append({
                "severity": "MEDIUM",
                "issue": f"Table '{table}': injection probe '{param_name}={payload}' triggered a 500 error — possible SQL error leakage",
                "payload": payload,
            })
    return findings


def scan_injections(client, tables, label="anon"):
    findings = []

    if not tables:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No tables available for injection testing",
        })
        return findings

    test_tables = tables[:5]

    for table in test_tables:
        status, rows, _ = client.get(f"/rest/v1/{table}", params={"limit": "1", "select": "id"})
        if status != 200 or not isinstance(rows, list) or not rows:
            continue

        findings += _probe_injection(client, table, "order", POSTGREST_ORDER_INJECTIONS)
        findings += _probe_injection(client, table, "id", POSTGREST_FILTER_INJECTIONS)
        findings += _probe_injection(client, table, "select", POSTGREST_SELECT_INJECTIONS)

    if not any(f["severity"] in ("HIGH", "MEDIUM") for f in findings):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] PostgREST injection probes did not trigger obvious SQL errors or data leakage",
        })

    return findings


def scan_mass_assignment(client, tables, label="anon"):
    findings = []
    privileged_fields = [
        "is_admin", "admin", "role", "is_superuser", "is_staff",
        "permissions", "verified", "email_verified", "is_active",
        "balance", "credits",
    ]

    for table in tables[:5]:
        for field in privileged_fields:
            payload = {field: True}
            status, data, _ = client.post(f"/rest/v1/{table}", body=payload)
            if status in (200, 201):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"[{label}] Table '{table}': mass assignment — INSERT with privileged field '{field}' accepted",
                })
            status, data, _ = client.patch(
                f"/rest/v1/{table}",
                body={field: True},
                params={"limit": "1"},
            )
            if status in (200, 204):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"[{label}] Table '{table}': mass assignment — UPDATE with privileged field '{field}' accepted",
                })

    if not any(f["severity"] == "CRITICAL" for f in findings):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No mass assignment vulnerabilities detected on probed tables",
        })

    return findings
