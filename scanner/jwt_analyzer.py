import base64
import json
import time


SENSITIVE_ROLES = {"service_role", "supabase_admin"}


def _decode_part(part):
    padded = part + "=" * (-len(part) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def analyze(token, label="anon_key"):
    findings = []
    parts = token.split(".")
    if len(parts) != 3:
        return [{"severity": "HIGH", "issue": f"[{label}] Malformed JWT — not a valid 3-part token"}]

    header = _decode_part(parts[0])
    payload = _decode_part(parts[1])

    if not header or not payload:
        return [{"severity": "HIGH", "issue": f"[{label}] JWT segments could not be base64-decoded"}]

    alg = header.get("alg", "")
    if alg == "none":
        findings.append({
            "severity": "CRITICAL",
            "issue": f"[{label}] Algorithm is 'none' — signature verification is completely disabled",
        })
    elif alg in ("HS256", "HS384", "HS512"):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Uses symmetric algorithm {alg}. If the signing secret leaks, arbitrary tokens can be forged.",
        })

    role = payload.get("role", "")
    if role in SENSITIVE_ROLES:
        findings.append({
            "severity": "CRITICAL",
            "issue": f"[{label}] Token role is '{role}' — this key bypasses Row Level Security on every table. Never embed in client-side code.",
        })
    elif role == "anon":
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Token role is 'anon'. Access is limited to what RLS policies permit for unauthenticated users.",
        })

    exp = payload.get("exp")
    iat = payload.get("iat")
    now = int(time.time())

    if exp is None:
        findings.append({
            "severity": "HIGH",
            "issue": f"[{label}] No expiration (exp) claim — token is valid indefinitely if leaked",
        })
    else:
        remaining = exp - now
        years = remaining / (365.25 * 24 * 3600)
        issued = time.strftime("%Y-%m-%d", time.gmtime(iat)) if iat else "unknown"
        expires = time.strftime("%Y-%m-%d", time.gmtime(exp))

        if remaining < 0:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Token is expired (expired {expires})",
            })
        elif years > 5:
            findings.append({
                "severity": "MEDIUM",
                "issue": f"[{label}] Token expires {expires} (~{years:.1f} years away). Long-lived keys expand the window of impact if leaked.",
            })

        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Issued {issued} | Expires {expires} | Remaining {max(0, remaining) // 86400} days",
        })

    ref = payload.get("ref", "")
    iss = payload.get("iss", "")
    if ref:
        findings.append({
            "severity": "LOW",
            "issue": f"[{label}] JWT payload exposes project ref '{ref}' and issuer '{iss}' in plaintext — anyone who holds this token knows your project ID",
        })

    return findings
