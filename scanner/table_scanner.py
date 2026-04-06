import json
import time
import uuid
from typing import List, Dict, Any, Tuple, Optional

SENSITIVE_COLUMN_PATTERNS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "private_key", "credit_card", "card_number", "cvv", "ssn",
    "social_security", "bank_account", "stripe", "twilio", "sendgrid",
    "firebase", "aws_", "gcp_", "azure_", "otp", "pin", "dob",
    "date_of_birth", "national_id", "passport", "salary", "income",
    "hash", "encrypted", "auth_token", "refresh_token", "access_token",
    "webhook", "private", "internal", "jwt", "bearer", "signing_key",
]

def _generate_test_id() -> str:
    return f"scanner_test_{uuid.uuid4().hex[:8]}"

def _flag_sensitive_columns(columns: List[str]) -> List[str]:
    hits = []
    for col in columns:
        lower = col.lower()
        for pattern in SENSITIVE_COLUMN_PATTERNS:
            if pattern in lower:
                hits.append(col)
                break
    return hits

def _cleanup_test_data(client, table: str, test_id: str) -> None:
    try:
        client.delete(f"/rest/v1/{table}", params={"test_id": f"eq.{test_id}"})
    except:
        pass

def _try_write(client, table: str, columns: List[str]) -> Tuple[bool, str]:
    test_id = _generate_test_id()
    payload = {"test_id": test_id, "_scanner_probe": True}
    
    for required in ["id", "created_at", "updated_at"]:
        if required in columns and required not in payload:
            if required == "id":
                payload["id"] = test_id
    
    try:
        status, data, _ = client.post(f"/rest/v1/{table}", body=payload)
        if status in (200, 201):
            _cleanup_test_data(client, table, test_id)
            return True, f"INSERT succeeded with anon key (test ID {test_id} cleaned up)"
        return False, None
    except:
        return False, None

def _try_update(client, table: str) -> Tuple[bool, str]:
    test_id = _generate_test_id()
    try:
        status, data, _ = client.patch(
            f"/rest/v1/{table}",
            body={"_scanner_probe": 1, "test_id": test_id},
            params={"limit": "1"}
        )
        if status in (200, 204):
            return True, "UPDATE succeeded — rows can be modified without authentication"
        return False, None
    except:
        return False, None

def _try_delete(client, table: str) -> Tuple[bool, str]:
    try:
        status, data, _ = client.delete(f"/rest/v1/{table}", params={"limit": "1"})
        if status in (200, 204):
            return True, "DELETE succeeded — rows can be deleted without authentication"
        return False, None
    except:
        return False, None

def scan_tables(client, label: str = "anon", max_rows: int = 10, delay: float = 0.3) -> Tuple[List[Dict], List[str]]:
    findings = []
    tables = []

    try:
        status, schema, _ = client.get("/rest/v1/")
        if status != 200 or not isinstance(schema, dict):
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] OpenAPI schema not accessible (status {status})",
            })
            return findings, tables

        paths = schema.get("paths", {})
        tables = sorted(set(
            p.strip("/").split("/")[0]
            for p in paths
            if p.startswith("/") and not p.startswith("/rpc") and p.count("/") == 1 and len(p.strip("/")) > 0
        ))

        if not tables:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] No publicly listed tables found in OpenAPI schema",
            })
            return findings, tables

        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] OpenAPI schema lists {len(tables)} accessible table(s)",
            "tables": tables[:10],
        })

        for table in tables:
            time.sleep(delay)
            
            try:
                status, rows, _ = client.get(
                    f"/rest/v1/{table}",
                    params={"limit": str(max_rows), "select": "*"},
                )

                if status == 200 and isinstance(rows, list):
                    if len(rows) > 0:
                        columns = list(rows[0].keys())
                        sensitive = _flag_sensitive_columns(columns)
                        
                        findings.append({
                            "severity": "HIGH",
                            "issue": f"[{label}] Table '{table}' is publicly readable — returned {len(rows)} row(s)",
                            "columns": ", ".join(columns[:15]),
                        })

                        if sensitive:
                            findings.append({
                                "severity": "CRITICAL",
                                "issue": f"[{label}] Table '{table}' contains sensitive columns: {', '.join(sensitive[:10])}",
                            })
                        
                        ok, msg = _try_write(client, table, columns)
                        if ok and msg:
                            findings.append({"severity": "CRITICAL", "issue": f"[{label}] Table '{table}': {msg}"})
                        
                        ok, msg = _try_update(client, table)
                        if ok and msg:
                            findings.append({"severity": "CRITICAL", "issue": f"[{label}] Table '{table}': {msg}"})
                        
                        ok, msg = _try_delete(client, table)
                        if ok and msg:
                            findings.append({"severity": "CRITICAL", "issue": f"[{label}] Table '{table}': {msg}"})
                    
                    elif len(rows) == 0:
                        findings.append({
                            "severity": "LOW",
                            "issue": f"[{label}] Table '{table}' is reachable but returned 0 rows — may be empty or RLS restricts access",
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
            except Exception as e:
                findings.append({
                    "severity": "INFO",
                    "issue": f"[{label}] Table '{table}' scan failed",
                    "error": str(e)[:100],
                })

    except Exception as e:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Table discovery failed",
            "error": str(e)[:100],
        })

    return findings, tables

def scan_rpc(client, label: str = "anon") -> List[Dict]:
    findings = []
    
    try:
        status, schema, _ = client.get("/rest/v1/")
        if status != 200 or not isinstance(schema, dict):
            return findings

        paths = schema.get("paths", {})
        rpc_functions = sorted(p for p in paths if p.startswith("/rpc/"))

        if rpc_functions:
            findings.append({
                "severity": "MEDIUM",
                "issue": f"[{label}] {len(rpc_functions)} RPC function(s) exposed: each should require proper auth",
                "functions": rpc_functions[:10],
            })

            for fn in rpc_functions[:5]:
                try:
                    time.sleep(0.3)
                    status, data, _ = client.post(fn, body={})
                    if status in (200, 201):
                        findings.append({
                            "severity": "HIGH",
                            "issue": f"[{label}] RPC function '{fn}' executed with empty body and anon key",
                        })
                    elif status == 400:
                        findings.append({
                            "severity": "LOW",
                            "issue": f"[{label}] RPC function '{fn}' rejected empty body (expected for parameterized functions)",
                        })
                except:
                    pass
        else:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] No RPC functions exposed in schema",
            })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] RPC scan failed",
            "error": str(e)[:100],
        })

    return findings

def brute_common_tables(client, label: str = "anon", custom_tables: Optional[List[str]] = None, delay: float = 0.2) -> Tuple[List[Dict], List[str]]:
    findings = []
    
    default_tables = [
        "users", "user", "profiles", "profile", "accounts", "account",
        "admin", "admins", "employees", "staff", "customers", "clients",
        "orders", "payments", "transactions", "invoices", "subscriptions",
        "logs", "audit_logs", "events", "sessions", "tokens",
        "messages", "notifications", "settings", "config", "secrets",
        "api_keys", "webhooks", "files", "uploads", "documents",
        "members", "teams", "organizations", "roles", "permissions",
    ]
    
    tables_to_try = custom_tables if custom_tables else default_tables
    found = []

    for table in tables_to_try[:30]:
        time.sleep(delay)
        try:
            status, rows, _ = client.get(f"/rest/v1/{table}", params={"limit": "1", "select": "*"})
            if status == 200 and isinstance(rows, list):
                found.append(table)
        except:
            pass

    if found:
        findings.append({
            "severity": "HIGH",
            "issue": f"[{label}] {len(found)} common table(s) accessible without auth",
            "tables": found[:15],
        })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No common table names responded to brute-force probe",
        })

    return findings, found
