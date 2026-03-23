

import time


def scan_auth_config(client, label="anon"):
    findings = []

    status, data, _ = client.get("/auth/v1/settings")
    if status == 200 and isinstance(data, dict):
        if not data.get("disable_signup", True):
            findings.append({
                "severity": "MEDIUM",
                "issue": f"[{label}] Open signup is enabled — anyone on the internet can register an account",
            })

        providers = [
            k for k, v in data.get("external", {}).items()
            if isinstance(v, dict) and v.get("enabled")
        ]
        if providers:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] OAuth providers enabled: {', '.join(providers)}",
            })

        mailer_autoconfirm = data.get("mailer_autoconfirm", False)
        if mailer_autoconfirm:
            findings.append({
                "severity": "MEDIUM",
                "issue": f"[{label}] Email auto-confirm is ON — users are not required to verify their email address",
            })

        sms_autoconfirm = data.get("sms_autoconfirm", False)
        if sms_autoconfirm:
            findings.append({
                "severity": "MEDIUM",
                "issue": f"[{label}] SMS auto-confirm is ON — phone numbers are not verified",
            })

    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] /auth/v1/settings returned {status} — settings endpoint is not public",
        })

    return findings


def scan_email_enumeration(client, label="anon"):
    findings = []

    probes = [
        ("admin@gmail.com", "likely-registered"),
        ("zxqprobexzq99871@nonexistentdomain.xyz", "likely-not-registered"),
    ]

    responses = []
    for email, note in probes:
        status, data, _ = client.post("/auth/v1/recover", body={"email": email})
        msg = ""
        if isinstance(data, dict):
            msg = data.get("error_description") or data.get("msg") or data.get("message") or data.get("error") or ""
        responses.append((status, str(msg).strip(), note))

    if len(responses) == 2:
        s1, m1, _ = responses[0]
        s2, m2, _ = responses[1]

        if s1 != s2:
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] Password reset returns different HTTP status codes for registered vs unregistered emails ({s1} vs {s2}) — email enumeration possible",
            })
        elif m1 != m2:
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] Password reset returns different error messages for registered vs unregistered emails — email enumeration possible",
                "registered_response": m1,
                "unregistered_response": m2,
            })
        else:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Password reset returns consistent responses — resists email enumeration",
            })

        if s1 == 429 or s2 == 429:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Rate limiting active on /auth/v1/recover (429 returned)",
            })

    return findings


def scan_auth_endpoints(client, label="anon"):
    findings = []

    status, data, _ = client.get("/auth/v1/admin/users")
    if status == 200 and isinstance(data, dict):
        users = data.get("users", [])
        findings.append({
            "severity": "CRITICAL",
            "issue": f"[{label}] Admin user listing is OPEN — {len(users)} user(s) exposed with full profile data",
        })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Admin user endpoint returned {status} — properly restricted",
        })

    status, data, _ = client.get("/auth/v1/user")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "issue": f"[{label}] /auth/v1/user returns 200 with anon token — check if user data is leaking",
        })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] /auth/v1/user returned {status} without a valid session (expected)",
        })

    brute_payloads = [
        {"email": "admin@example.com", "password": "admin"},
        {"email": "admin@example.com", "password": "password"},
        {"email": "test@test.com", "password": "test"},
    ]

    statuses = []
    for payload in brute_payloads:
        status, _, _ = client.post("/auth/v1/token?grant_type=password", body=payload)
        statuses.append(status)
        if status == 429:
            break

    if all(s == 429 for s in statuses):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Brute-force protection active on login endpoint (all probes rate-limited)",
        })
    elif any(s == 200 for s in statuses):
        findings.append({
            "severity": "CRITICAL",
            "issue": f"[{label}] Login succeeded with a common password — account with weak credentials exists",
        })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Login endpoint rejected all weak-credential probes",
        })

    return findings


def scan_magic_link(client, label="anon"):
    findings = []
    status, data, _ = client.post(
        "/auth/v1/magiclink",
        body={"email": "scanner-probe@nonexistentdomain.xyz"},
    )
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "issue": f"[{label}] Magic link endpoint accepts any email without rate-limiting visible — potential for spam/abuse",
        })
    elif status == 429:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Magic link endpoint is rate-limited",
        })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Magic link endpoint returned {status}",
        })
    return findings
