import json
import time
import random
import uuid
from typing import List, Dict, Any, Tuple, Optional

INTEGER_ID_PROBES = [1, 2, 3, 5, 10, 100, 999, 1000, 9999]
UUID_PROBES = [
    "00000000-0000-0000-0000-000000000001",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "12345678-1234-1234-1234-123456789012",
]

def _generate_uuid_probes(count: int = 5) -> List[str]:
    probes = UUID_PROBES.copy()
    for _ in range(count - len(probes)):
        probes.append(str(uuid.uuid4()))
    return probes[:count]

def _detect_id_column(row: Dict) -> Tuple[Optional[str], Optional[Any]]:
    priority_fields = ["id", "uuid", "user_id", "account_id", "record_id", "pk", "uid"]
    for candidate in priority_fields:
        if candidate in row:
            return candidate, row[candidate]
    
    for key, val in row.items():
        key_lower = key.lower()
        if "id" in key_lower or "uuid" in key_lower or "key" in key_lower:
            return key, val
    return None, None

def _is_uuid_like(val: Any) -> bool:
    s = str(val)
    if len(s) == 36 and s.count("-") == 4:
        return True
    return False

def _is_int_id(val: Any) -> bool:
    try:
        int_val = int(val)
        return 0 < int_val < 999999999
    except (ValueError, TypeError):
        return False

def _contains_sensitive_data(row: Dict) -> List[str]:
    sensitive = []
    sensitive_fields = ["email", "phone", "address", "ssn", "password", "token", "api_key", "credit_card"]
    for field in sensitive_fields:
        if field in row or any(field in k.lower() for k in row.keys()):
            sensitive.append(field)
    return sensitive

def scan_idor(client, tables: List[str], label: str = "anon", delay: float = 0.3, max_probes: int = 10) -> List[Dict]:
    findings = []
    
    if not tables:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No tables available for IDOR testing",
        })
        return findings
    
    for table in tables:
        time.sleep(delay)
        
        try:
            status, rows, _ = client.get(f"/rest/v1/{table}", params={"limit": "5", "select": "*"})
            if status != 200 or not isinstance(rows, list) or not rows:
                continue
            
            id_col, sample_val = _detect_id_column(rows[0])
            if not id_col:
                continue
            
            sampled_ids = [str(r.get(id_col)) for r in rows[:3] if r.get(id_col) is not None]
            sampled_ids = [sid for sid in sampled_ids if sid and sid != "None"]
            
            if _is_uuid_like(sample_val):
                probes = _generate_uuid_probes(min(max_probes, 10))
                op = "eq"
            elif _is_int_id(sample_val):
                base_probes = INTEGER_ID_PROBES.copy()
                for sid in sampled_ids[:2]:
                    try:
                        int_sid = int(sid)
                        base_probes.extend([int_sid + 1, int_sid + 10, int_sid * 2])
                    except:
                        pass
                probes = list(set(base_probes))[:max_probes]
                op = "eq"
            else:
                continue
            
            accessible_ids = []
            accessed_data = []
            
            for probe_id in probes:
                time.sleep(delay * 0.5)
                try:
                    params = {"select": "*", id_col: f"{op}.{probe_id}"}
                    s, data, _ = client.get(f"/rest/v1/{table}", params=params)
                    
                    if s == 200 and isinstance(data, list) and len(data) > 0:
                        probe_str = str(probe_id)
                        if probe_str not in sampled_ids:
                            accessible_ids.append(probe_str)
                            accessed_data.extend(data[:1])
                except:
                    continue
            
            if accessible_ids:
                sensitive_in_found = []
                for record in accessed_data[:3]:
                    sensitive_in_found.extend(_contains_sensitive_data(record))
                
                severity = "CRITICAL" if sensitive_in_found else "HIGH"
                
                findings.append({
                    "severity": severity,
                    "issue": f"[{label}] Table '{table}': IDOR vulnerability — {len(accessible_ids)} record(s) accessible by probing '{id_col}'",
                    "accessible_ids": accessible_ids[:5],
                    "sensitive_data_found": sensitive_in_found[:5] if sensitive_in_found else None,
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "issue": f"[{label}] Table '{table}': ID probes on '{id_col}' returned no accessible foreign records",
                })
            
            if len(rows) > 1 and len(set(sampled_ids)) > 1:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": f"[{label}] Table '{table}': multiple rows returned with different '{id_col}' values — verify RLS isolation",
                    "sample_ids": sampled_ids[:5],
                })
        
        except Exception as e:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Table '{table}': IDOR scan failed",
                "error": str(e)[:100],
            })
    
    return findings

def scan_horizontal_privilege_escalation(client, tables: List[str], label: str = "anon", delay: float = 0.5) -> List[Dict]:
    findings = []
    
    for table in tables:
        time.sleep(delay)
        
        try:
            status, rows, _ = client.get(f"/rest/v1/{table}", params={"limit": "5", "select": "*"})
            if status != 200 or not isinstance(rows, list) or len(rows) < 2:
                continue
            
            id_col, _ = _detect_id_column(rows[0])
            if not id_col:
                continue
            
            ids = [str(r.get(id_col)) for r in rows if r.get(id_col) is not None]
            ids = list(set(ids))
            
            if len(ids) < 2:
                continue
            
            user_cols = [k for k in rows[0].keys() if "user" in k.lower() or "owner" in k.lower() or "account" in k.lower()]
            user_values = {}
            
            for row in rows:
                for col in user_cols:
                    if col in row and row[col]:
                        user_values[col] = row[col]
                        break
            
            test_id_pairs = [(ids[0], ids[1])]
            if len(ids) >= 3:
                test_id_pairs.append((ids[0], ids[2]))
            
            vulnerabilities = []
            
            for id_a, id_b in test_id_pairs[:3]:
                time.sleep(delay * 0.3)
                try:
                    s, data, _ = client.get(
                        f"/rest/v1/{table}",
                        params={"select": "*", id_col: f"in.({id_a},{id_b})"},
                    )
                    
                    if s == 200 and isinstance(data, list):
                        returned_ids = [str(item.get(id_col)) for item in data if item.get(id_col)]
                        
                        if len(returned_ids) >= 2 and set([id_a, id_b]).issubset(set(returned_ids)):
                            vulnerabilities.append(f"bulk fetch returned both IDs {id_a} and {id_b}")
                        
                        if len(data) >= 2:
                            unique_users = set()
                            for item in data:
                                for col in user_cols:
                                    if col in item and item[col]:
                                        unique_users.add(str(item[col]))
                            
                            if len(unique_users) >= 2:
                                vulnerabilities.append(f"bulk fetch returned data from {len(unique_users)} different users/owners")
                except:
                    continue
            
            if vulnerabilities:
                findings.append({
                    "severity": "HIGH",
                    "issue": f"[{label}] Table '{table}': horizontal privilege escalation possible via bulk ID filters",
                    "details": vulnerabilities[:3],
                    "id_column": id_col,
                    "user_columns": user_cols[:3] if user_cols else None,
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "issue": f"[{label}] Table '{table}': no horizontal escalation detected via bulk ID probing",
                })
        
        except Exception as e:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Table '{table}': horizontal escalation scan failed",
                "error": str(e)[:100],
            })
    
    if not any(f.get("severity") in ("HIGH", "CRITICAL") for f in findings):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No horizontal privilege escalation patterns detected across tested tables",
        })
    
    return findings
