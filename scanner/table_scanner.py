import json


SENSITIVE_COLUMN_PATTERNS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "private_key", "credit_card", "card_number", "cvv", "ssn",
    "social_security", "bank_account", "stripe", "twilio", "sendgrid",
    "firebase", "aws_", "gcp_", "azure_", "otp", "pin", "dob",
    "date_of_birth", "national_id", "passport", "salary", "income",
    "hash", "encrypted", "auth_token", "refresh_token", "access_token",
    "webhook", "private", "internal",
]

WRITE_PROBE_PAYLOAD = {"_scanner_probe": True, "_delete_me": True}


def _flag_sensitive_columns(columns):
    hits = []
    for col in columns:
        lower = col.lower()
        for pattern in SENSITIVE_COLUMN_PATTERNS:
            if pattern in lower:
                hits.append(col)
                break
    return hits


def _try_write(client, table):
    status, data, _ = client.post(f"/rest/v1/{table}", body=WRITE_PROBE_PAYLOAD)
    if status in (200, 201):
        return True, "INSERT succeeded — table is writable without authentication"
    return False, None


def _try_delete(client, table):
    status, data, _ = client.delete(f"/rest/v1/{table}", params={"limit": "1"})
    if status in (200, 204):
        return True, "DELETE succeeded — rows can be deleted without authentication"
    return False, None


def _try_update(client, table):
    status, data, _ = client.patch(f"/rest/v1/{table}", body={"_probe": 1}, params={"limit": "1"})
    if status in (200, 204):
        return True, "UPDATE succeeded — rows can be modified without authentication"
    return False, None


def scan_tables(client, label="anon"):
    findings = []
    tables = []

    status, schema, _ = client.get("/rest/v1/")
    if status != 200 or not isinstance(schema, dict):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] OpenAPI schema not accessible (status {status})",
        })
        return findings, tables

    paths = schema.get("paths", {})
    tables = sorted(
        set(
            p.strip("/").split("/")[0]
            for p in paths
            if p.startswith("/") and not p.startswith("/rpc") and p.count("/") == 1
        )
    )

    if not tables:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No publicly listed tables found in OpenAPI schema",
        })
        return findings, tables

    findings.append({
        "severity": "INFO",
        "issue": f"[{label}] OpenAPI schema lists {len(tables)} table(s): {', '.join(tables)}",
    })

    for table in tables:
        status, rows, headers = client.get(
            f"/rest/v1/{table}",
            params={"limit": "5", "select": "*"},
        )

        if status == 200 and isinstance(rows, list) and len(rows) > 0:
            columns = list(rows[0].keys())
            sensitive = _flag_sensitive_columns(columns)

            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] Table '{table}' is publicly readable — returned {len(rows)} row(s)",
                "columns": ", ".join(columns),
            })

            if sensitive:
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"[{label}] Table '{table}' contains sensitive-looking columns: {', '.join(sensitive)}",
                })

            ok, msg = _try_write(client, table)
            if ok:
                findings.append({"severity": "CRITICAL", "issue": f"[{label}] Table '{table}': {msg}"})

            ok, msg = _try_update(client, table)
            if ok:
                findings.append({"severity": "CRITICAL", "issue": f"[{label}] Table '{table}': {msg}"})

            ok, msg = _try_delete(client, table)
            if ok:
                findings.append({"severity": "CRITICAL", "issue": f"[{label}] Table '{table}': {msg}"})

        elif status == 200 and isinstance(rows, list) and len(rows) == 0:
            findings.append({
                "severity": "LOW",
                "issue": f"[{label}] Table '{table}' is reachable but returned 0 rows — RLS may be enforcing access control or table is empty",
            })

        elif status in (401, 403):
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Table '{table}' blocked with {status} — access control is working",
            })
        else:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Table '{table}' returned status {status}",
            })

    return findings, tables


def scan_rpc(client, label="anon"):
    findings = []
    status, schema, _ = client.get("/rest/v1/")
    if status != 200 or not isinstance(schema, dict):
        return findings

    paths = schema.get("paths", {})
    rpc_functions = sorted(p for p in paths if p.startswith("/rpc/"))

    if rpc_functions:
        findings.append({
            "severity": "MEDIUM",
            "issue": f"[{label}] {len(rpc_functions)} RPC function(s) exposed: {', '.join(rpc_functions)}. Each should require proper auth.",
        })

        for fn in rpc_functions:
            status, data, _ = client.post(fn, body={})
            if status in (200, 201):
                findings.append({
                    "severity": "HIGH",
                    "issue": f"[{label}] RPC function '{fn}' executed successfully with no arguments and anon key",
                })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No RPC functions exposed in schema",
        })

    return findings


def brute_common_tables(client, label="anon"):
    findings = []

    common = [
        "users", "user", "profiles", "profile", "accounts", "account",
        "admin", "admins", "employees", "staff", "customers", "clients",
        "orders", "payments", "transactions", "invoices", "subscriptions",
        "logs", "audit_logs", "events", "sessions", "tokens",
        "messages", "notifications", "settings", "config", "secrets",
        "api_keys", "webhooks", "files", "uploads", "documents",
    ]

    found = []
    for table in common:
        status, rows, _ = client.get(f"/rest/v1/{table}", params={"limit": "1", "select": "*"})
        if status == 200 and isinstance(rows, list):
            found.append(table)

    if found:
        findings.append({
            "severity": "HIGH",
            "issue": f"[{label}] Common table names accessible without auth: {', '.join(found)}",
        })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No common table names responded to brute-force probe",
        })

    return findings, found
