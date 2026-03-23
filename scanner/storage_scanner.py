SENSITIVE_EXTENSIONS = [
    ".env", ".sql", ".pem", ".key", ".p12", ".pfx", ".crt", ".cer",
    ".csv", ".xlsx", ".xls", ".json", ".bak", ".dump", ".tar", ".gz",
    ".zip", ".rar", ".log", ".conf", ".config", ".yml", ".yaml",
    ".ini", ".htpasswd", ".htaccess", ".DS_Store",
]

SENSITIVE_PATTERNS = [
    "backup", "dump", "export", "secret", "private", "credential",
    "password", "passwd", "token", "invoice", "user", "users",
    "database", "db_", "_db", "prod", "production", "staging",
    "admin", "internal", "sensitive", "confidential", "personal",
    "pii", "gdpr", "financial", "payroll", "salary",
]


def _is_sensitive(name):
    lower = name.lower()
    for ext in SENSITIVE_EXTENSIONS:
        if lower.endswith(ext):
            return True, f"extension '{ext}'"
    for pattern in SENSITIVE_PATTERNS:
        if pattern in lower:
            return True, f"pattern '{pattern}'"
    return False, None


def scan_storage(client, label="anon"):
    findings = []

    status, buckets, _ = client.get("/storage/v1/bucket")

    if status in (401, 403):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Storage bucket listing requires authentication — properly restricted",
        })
        return findings

    if status != 200 or not isinstance(buckets, list):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Storage returned status {status} — may not be configured",
        })
        return findings

    if not buckets:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No storage buckets found",
        })
        return findings

    findings.append({
        "severity": "MEDIUM",
        "issue": f"[{label}] Storage bucket list is accessible with anon key — {len(buckets)} bucket(s) found: {', '.join(b.get('id', b.get('name', '?')) for b in buckets)}",
    })

    for bucket in buckets:
        bid = bucket.get("id") or bucket.get("name", "unknown")
        is_public = bucket.get("public", False)
        size_limit = bucket.get("file_size_limit")
        allowed_types = bucket.get("allowed_mime_types")

        if is_public:
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] Bucket '{bid}' is PUBLIC — all files are accessible without any authentication",
            })
        else:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Bucket '{bid}' is private",
            })

        if size_limit is None:
            findings.append({
                "severity": "LOW",
                "issue": f"[{label}] Bucket '{bid}' has no file size limit configured",
            })

        if not allowed_types:
            findings.append({
                "severity": "LOW",
                "issue": f"[{label}] Bucket '{bid}' has no MIME type restrictions — any file type can be uploaded",
            })

        list_status, files, _ = client.post(
            f"/storage/v1/object/list/{bid}",
            body={"limit": 100, "offset": 0, "prefix": ""},
        )

        if list_status == 200 and isinstance(files, list):
            if files:
                findings.append({
                    "severity": "MEDIUM" if is_public else "LOW",
                    "issue": f"[{label}] Bucket '{bid}': {len(files)} file(s) listable with anon key",
                })
                for f in files:
                    fname = f.get("name", "")
                    flagged, reason = _is_sensitive(fname)
                    if flagged:
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": f"[{label}] Bucket '{bid}': sensitive file '{fname}' detected ({reason})",
                        })
        elif list_status in (401, 403):
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Bucket '{bid}' file listing is restricted",
            })

    return findings
