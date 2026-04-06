import urllib.parse
import time
import json
from typing import List, Dict, Any, Optional

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

def _url_encode_payload(payload: str) -> str:
    return urllib.parse.quote(payload, safe='')

def _probe_injection(client, table: str, param_name: str, payloads: List[str], extra_params: Optional[Dict] = None, delay: float = 0.5) -> List[Dict]:
    findings = []
    
    for payload in payloads:
        time.sleep(delay)
        encoded_payload = _url_encode_payload(payload)
        params = {param_name: encoded_payload, "limit": "1"}
        if extra_params:
            params.update(extra_params)
        
        try:
            status, data, response_text = client.get(f"/rest/v1/{table}", params=params)
            
            if status == 200 and isinstance(data, list) and len(data) > 0:
                findings.append({
                    "severity": "HIGH",
                    "issue": f"Table '{table}': injection probe '{param_name}={payload}' returned data — possible filter bypass",
                    "payload": payload,
                    "status_code": status,
                })
            elif status == 500:
                error_analysis = "SQL error" if any(x in str(data).lower() for x in ["sql", "postgres", "syntax", "relation"]) else "server error"
                findings.append({
                    "severity": "MEDIUM" if error_analysis == "SQL error" else "LOW",
                    "issue": f"Table '{table}': injection probe '{param_name}={payload}' triggered a {status} error — possible {error_analysis} leakage",
                    "payload": payload,
                    "error": str(data)[:200],
                })
            elif status == 400 and "syntax" in str(data).lower():
                findings.append({
                    "severity": "LOW",
                    "issue": f"Table '{table}': injection probe '{param_name}={payload}' triggered syntax error — query structure may be vulnerable",
                    "payload": payload,
                })
        except Exception as e:
            findings.append({
                "severity": "INFO",
                "issue": f"Table '{table}': injection probe '{param_name}={payload}' failed with exception",
                "error": str(e)[:100],
            })
    
    return findings

def _get_table_schema(client, table: str) -> Dict:
    try:
        status, data, _ = client.get(f"/rest/v1/{table}", params={"limit": "0", "select": "*"})
        if status == 200 and isinstance(data, dict) and "columns" in data:
            return {col.get("name"): col for col in data.get("columns", [])}
    except:
        pass
    return {}

def _cleanup_test_data(client, table: str, test_id: str) -> None:
    try:
        client.delete(f"/rest/v1/{table}", params={"test_id": f"eq.{test_id}"})
    except:
        pass

def scan_injections(client, tables: List[str], label: str = "anon", max_tables: int = 10, delay: float = 0.5) -> List[Dict]:
    findings = []

    if not tables:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No tables available for injection testing",
        })
        return findings

    test_tables = tables[:max_tables]

    for table in test_tables:
        try:
            status, rows, _ = client.get(f"/rest/v1/{table}", params={"limit": "1", "select": "id"})
            if status != 200 or not isinstance(rows, list) or not rows:
                continue
            
            table_findings = []
            table_findings += _probe_injection(client, table, "order", POSTGREST_ORDER_INJECTIONS, delay=delay)
            table_findings += _probe_injection(client, table, "id", POSTGREST_FILTER_INJECTIONS, delay=delay)
            table_findings += _probe_injection(client, table, "select", POSTGREST_SELECT_INJECTIONS, delay=delay)
            
            findings.extend(table_findings)
            
            if table_findings:
                time.sleep(delay)
        except Exception as e:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Table '{table}': injection testing failed",
                "error": str(e)[:100],
            })

    if not any(f.get("severity") in ("HIGH", "MEDIUM", "CRITICAL") for f in findings):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] PostgREST injection probes did not trigger obvious SQL errors or data leakage",
        })

    return findings

def scan_mass_assignment(client, tables: List[str], label: str = "anon", max_tables: int = 10, dry_run: bool = True) -> List[Dict]:
    findings = []
    
    privileged_fields = [
        "is_admin", "admin", "role", "is_superuser", "is_staff",
        "permissions", "verified", "email_verified", "is_active",
        "balance", "credits", "is_verified", "is_approved", "is_banned",
        "level", "access_level", "privilege_level",
    ]

    test_tables = tables[:max_tables]

    for table in test_tables:
        try:
            schema = _get_table_schema(client, table)
            existing_fields = set(schema.keys())
            testable_fields = [f for f in privileged_fields if f in existing_fields]
            
            if not testable_fields:
                continue
            
            for field in testable_fields[:3]:
                test_id = f"test_{int(time.time())}_{hash(field) % 10000}"
                
                if dry_run:
                    status, data, _ = client.post(f"/rest/v1/{table}", body={field: True, "test_id": test_id})
                    if status in (200, 201):
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": f"[{label}] Table '{table}': mass assignment vulnerability — INSERT with privileged field '{field}' accepted (dry run)",
                            "field": field,
                            "status_code": status,
                        })
                        _cleanup_test_data(client, table, test_id)
                    
                    time.sleep(0.3)
                    
                    status, data, _ = client.patch(
                        f"/rest/v1/{table}",
                        body={field: True, "test_id": test_id},
                        params={"limit": "1"},
                    )
                    if status in (200, 204):
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": f"[{label}] Table '{table}': mass assignment vulnerability — UPDATE with privileged field '{field}' accepted (dry run)",
                            "field": field,
                            "status_code": status,
                        })
                    
                    time.sleep(0.3)
        except Exception as e:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Table '{table}': mass assignment testing failed",
                "error": str(e)[:100],
            })

    if not any(f.get("severity") == "CRITICAL" for f in findings):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No mass assignment vulnerabilities detected on probed tables",
        })

    return findings
