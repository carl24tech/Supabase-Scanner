
POLICY_INTROSPECTION_QUERIES = [
    "pg_policies",
    "information_schema.tables",
    "pg_tables",
    "pg_class",
    "pg_namespace",
]

DANGEROUS_POLICY_HINTS = [
    "true",
    "1=1",
    "auth.uid() is not null",
]


def _check_rls_via_count(client, table, label):
    findings = []

    status_anon, rows_anon, _ = client.get(
        f"/rest/v1/{table}", params={"select": "*", "limit": "1"}
    )

    status_head, _, head_headers = client.get(
        f"/rest/v1/{table}",
        params={"select": "count", "head": "true"},
        extra_headers={"Prefer": "count=exact"},
    )

    content_range = head_headers.get("Content-Range") or head_headers.get("content-range", "")

    if status_anon == 200 and isinstance(rows_anon, list) and len(rows_anon) > 0:
        if content_range and "/" in content_range:
            total = content_range.split("/")[-1]
            if total != "*" and total.isdigit():
                count = int(total)
                if count > 0:
                    severity = "CRITICAL" if count > 1000 else "HIGH" if count > 100 else "MEDIUM"
                    findings.append({
                        "severity": severity,
                        "issue": f"[{label}] Table '{table}' has RLS disabled or a permissive policy — {count} row(s) readable by anonymous users",
                        "row_count": count,
                    })
    return findings


def check_pg_catalog_exposure(client, label):
    findings = []

    catalog_tables = [
        "pg_policies",
        "pg_tables",
        "pg_roles",
        "pg_user",
        "pg_shadow",
        "pg_authid",
        "pg_stat_activity",
        "pg_hba_file_rules",
        "pg_config",
    ]

    exposed = []
    for tbl in catalog_tables:
        status, data, _ = client.get(f"/rest/v1/{tbl}", params={"limit": "1", "select": "*"})
        if status == 200 and isinstance(data, list) and len(data) > 0:
            exposed.append(tbl)
            if tbl == "pg_roles":
                roles = [r.get("rolname", "") for r in data]
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"[{label}] pg_roles is readable — database roles exposed: {', '.join(roles[:10])}",
                })
            elif tbl == "pg_policies":
                for policy in data[:5]:
                    polqual = str(policy.get("polqual", "")).lower()
                    for hint in DANGEROUS_POLICY_HINTS:
                        if hint in polqual:
                            findings.append({
                                "severity": "CRITICAL",
                                "issue": f"[{label}] RLS policy '{policy.get('polname')}' on table '{policy.get('tablename')}' uses permissive qualifier: '{polqual[:80]}'",
                            })
            elif tbl == "pg_stat_activity":
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"[{label}] pg_stat_activity is readable — live database queries and connection info exposed",
                })
            else:
                findings.append({
                    "severity": "HIGH",
                    "issue": f"[{label}] PostgreSQL system catalog '{tbl}' is readable via the REST API",
                })

    if not exposed:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] PostgreSQL system catalogs are not accessible via REST (expected)",
        })

    return findings


def scan_rls(client, tables, label="anon"):
    findings = []

    if not tables:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No tables available for RLS analysis",
        })
        return findings

    findings += check_pg_catalog_exposure(client, label)

    for table in tables:
        findings += _check_rls_via_count(client, table, label)

    status, data, _ = client.get(
        "/rest/v1/pg_policies",
        params={"select": "tablename,policyname,permissive,roles,cmd,qual", "limit": "50"},
    )
    if status == 200 and isinstance(data, list) and data:
        for policy in data:
            permissive = policy.get("permissive", "PERMISSIVE")
            qual = str(policy.get("qual", "")).lower()
            cmd = policy.get("cmd", "ALL")
            table_name = policy.get("tablename", "")
            policy_name = policy.get("policyname", "")

            if permissive == "PERMISSIVE" and qual in ("true", "(true)"):
                findings.append({
                    "severity": "HIGH",
                    "issue": f"[{label}] Table '{table_name}' has a PERMISSIVE {cmd} policy '{policy_name}' with qualifier 'true' — no restriction applied",
                })

    return findings


def estimate_data_exposure(client, tables, label="anon"):
    findings = []
    total_rows = 0
    exposed_tables = {}

    for table in tables:
        _, _, head_headers = client.get(
            f"/rest/v1/{table}",
            params={"select": "count", "head": "true"},
            extra_headers={"Prefer": "count=exact"},
        )
        content_range = head_headers.get("Content-Range") or head_headers.get("content-range", "")
        if content_range and "/" in content_range:
            part = content_range.split("/")[-1]
            if part.isdigit():
                count = int(part)
                exposed_tables[table] = count
                total_rows += count

    if total_rows > 0:
        severity = "CRITICAL" if total_rows > 10000 else "HIGH" if total_rows > 1000 else "MEDIUM"
        findings.append({
            "severity": severity,
            "issue": f"[{label}] Total publicly readable rows across all tables: {total_rows:,}",
            "breakdown": ", ".join(f"{t}={n}" for t, n in exposed_tables.items()),
        })

    return findings
