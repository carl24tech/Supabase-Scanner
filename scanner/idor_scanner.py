import json


INTEGER_ID_PROBES = list(range(1, 6))
UUID_PROBES = [
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
]


def _detect_id_column(row):
    for candidate in ("id", "uuid", "user_id", "account_id", "record_id", "pk"):
        if candidate in row:
            return candidate, row[candidate]
    for key, val in row.items():
        if "id" in key.lower():
            return key, val
    return None, None


def _is_uuid_like(val):
    s = str(val)
    return len(s) == 36 and s.count("-") == 4


def _is_int_id(val):
    try:
        int(val)
        return True
    except (ValueError, TypeError):
        return False


def scan_idor(client, tables, label="anon"):
    findings = []

    if not tables:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No tables available for IDOR testing",
        })
        return findings

    for table in tables:
        status, rows, _ = client.get(
            f"/rest/v1/{table}", params={"limit": "3", "select": "*"}
        )
        if status != 200 or not isinstance(rows, list) or not rows:
            continue

        id_col, sample_val = _detect_id_column(rows[0])
        if not id_col:
            continue

        if _is_uuid_like(sample_val):
            probes = UUID_PROBES
            op = "eq"
        elif _is_int_id(sample_val):
            probes = INTEGER_ID_PROBES
            op = "eq"
        else:
            continue

        accessible_ids = []
        for probe_id in probes:
            s, data, _ = client.get(
                f"/rest/v1/{table}",
                params={"select": "*", id_col: f"{op}.{probe_id}"},
            )
            if s == 200 and isinstance(data, list) and len(data) > 0:
                accessible_ids.append(probe_id)

        if accessible_ids:
            first_row = rows[0]
            user_fields = [k for k in first_row if "user" in k.lower() or "owner" in k.lower() or "email" in k.lower()]
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] Table '{table}': IDOR — records accessible by probing '{id_col}' directly (matched IDs: {accessible_ids})",
                "user_fields_present": ", ".join(user_fields) if user_fields else "none detected",
            })
        else:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Table '{table}': direct ID probes on '{id_col}' returned no rows (RLS may be isolating records per user)",
            })

        if len(rows) > 1:
            id_vals = [str(r.get(id_col)) for r in rows if r.get(id_col) is not None]
            if len(set(id_vals)) == len(id_vals):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": f"[{label}] Table '{table}': multiple rows with distinct '{id_col}' values returned without auth — cross-user data may be readable",
                    "sample_ids": ", ".join(id_vals[:5]),
                })

    return findings


def scan_horizontal_privilege_escalation(client, tables, label="anon"):
    findings = []

    for table in tables:
        status, rows, _ = client.get(
            f"/rest/v1/{table}", params={"limit": "2", "select": "*"}
        )
        if status != 200 or not isinstance(rows, list) or len(rows) < 2:
            continue

        id_col, _ = _detect_id_column(rows[0])
        if not id_col:
            continue

        ids = [str(r.get(id_col)) for r in rows if r.get(id_col) is not None]

        if len(ids) >= 2:
            id_a, id_b = ids[0], ids[1]
            s, data, _ = client.get(
                f"/rest/v1/{table}",
                params={"select": "*", id_col: f"in.({id_a},{id_b})"},
            )
            if s == 200 and isinstance(data, list) and len(data) == 2:
                findings.append({
                    "severity": "HIGH",
                    "issue": f"[{label}] Table '{table}': bulk ID fetch via 'in.(...)' filter returns records across different users — horizontal privilege escalation possible",
                })

    if not any(f["severity"] in ("HIGH", "CRITICAL") for f in findings):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No horizontal privilege escalation patterns detected via bulk ID probing",
        })

    return findings
