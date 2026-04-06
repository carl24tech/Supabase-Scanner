import time
import random
import string
from typing import List, Dict, Any, Optional

def _generate_random_email() -> str:
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"test_{random_str}@example.com"

def _safe_get_text(data: Any) -> str:
    if isinstance(data, dict):
        return str(data.get("error_description") or data.get("msg") or data.get("message") or data.get("error") or "")
    return str(data)

def scan_auth_config(client, label: str = "anon") -> List[Dict]:
    findings = []
    
    try:
        status, data, _ = client.get("/auth/v1/settings")
        
        if status == 200 and isinstance(data, dict):
            if not data.get("disable_signup", True):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": f"[{label}] Open signup is enabled — anyone on the internet can register an account",
                })
            
            external = data.get("external", {})
            if isinstance(external, dict):
                providers = [
                    k for k, v in external.items()
                    if isinstance(v, dict) and v.get("enabled", False)
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
        elif status == 401 or status == 403:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Auth settings endpoint requires authentication (status {status})",
            })
        else:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Auth settings endpoint returned {status}",
            })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Failed to scan auth config",
            "error": str(e)[:100],
        })
    
    return findings

def scan_email_enumeration(client, label: str = "anon", delay: float = 1.0) -> List[Dict]:
    findings = []
    
    registered_email = _generate_random_email()
    unregistered_email = _generate_random_email()
    
    time.sleep(delay)
    
    responses = []
    for email in [registered_email, unregistered_email]:
        try:
            start_time = time.time()
            status, data, _ = client.post("/auth/v1/recover", body={"email": email})
            response_time = time.time() - start_time
            message = _safe_get_text(data)
            responses.append((status, message, response_time))
            time.sleep(delay)
        except Exception as e:
            responses.append((None, str(e), 0))
    
    if len(responses) == 2:
        s1, m1, t1 = responses[0]
        s2, m2, t2 = responses[1]
        
        status_diff = s1 != s2 and s1 is not None and s2 is not None
        message_diff = m1 != m2 and m1 and m2
        time_diff = abs(t1 - t2) > 0.5
        
        if status_diff:
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] Password reset returns different HTTP status codes ({s1} vs {s2}) — email enumeration possible",
            })
        
        if message_diff:
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] Password reset returns different error messages — email enumeration possible",
                "registered_response": m1[:100],
                "unregistered_response": m2[:100],
            })
        
        if time_diff and not status_diff and not message_diff:
            findings.append({
                "severity": "MEDIUM",
                "issue": f"[{label}] Password reset response timing differs by {abs(t1-t2):.2f}s — potential timing-based enumeration",
            })
        
        if not status_diff and not message_diff and not time_diff:
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

def scan_auth_endpoints(client, label: str = "anon") -> List[Dict]:
    findings = []
    
    try:
        status, data, _ = client.get("/auth/v1/admin/users")
        if status == 200:
            users = []
            if isinstance(data, dict):
                users = data.get("users", [])
            findings.append({
                "severity": "CRITICAL",
                "issue": f"[{label}] Admin user listing is OPEN — {len(users)} user(s) exposed",
            })
        elif status in (401, 403):
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Admin user endpoint properly restricted (status {status})",
            })
        else:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] Admin user endpoint returned {status}",
            })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Admin user endpoint check failed",
            "error": str(e)[:100],
        })
    
    try:
        status, data, _ = client.get("/auth/v1/user")
        if status == 200:
            user_data = data if isinstance(data, dict) else {}
            user_id = user_data.get("id", "unknown")
            findings.append({
                "severity": "MEDIUM",
                "issue": f"[{label}] /auth/v1/user returns 200 with anon token — user data may be leaking (user {user_id})",
            })
        elif status == 401:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] /auth/v1/user properly requires authentication",
            })
    except Exception as e:
        pass
    
    probe_emails = [
        f"probe_{random.randint(1, 9999)}@test.com",
        f"security_{random.randint(1, 9999)}@scan.local",
    ]
    
    statuses = []
    for email in probe_emails:
        try:
            status, _, _ = client.post("/auth/v1/token?grant_type=password", body={"email": email, "password": "weak_password_123"})
            statuses.append(status)
            time.sleep(0.5)
            if status == 429:
                break
        except:
            statuses.append(None)
    
    rate_limited = any(s == 429 for s in statuses)
    if rate_limited:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Brute-force protection appears active (rate limiting detected)",
        })
    else:
        findings.append({
            "severity": "LOW",
            "issue": f"[{label}] No obvious rate limiting on login endpoint — consider implementing protection",
        })
    
    return findings

def scan_magic_link(client, label: str = "anon") -> List[Dict]:
    findings = []
    
    test_emails = [
        f"magic_{random.randint(1, 9999)}@test.com",
        f"probe_{random.randint(1, 9999)}@example.org",
    ]
    
    results = []
    for email in test_emails:
        try:
            status, data, _ = client.post("/auth/v1/magiclink", body={"email": email})
            message = _safe_get_text(data)
            results.append((status, message))
            time.sleep(0.5)
        except Exception as e:
            results.append((None, str(e)))
    
    success_count = sum(1 for s, _ in results if s == 200)
    
    if success_count == len(test_emails):
        findings.append({
            "severity": "MEDIUM",
            "issue": f"[{label}] Magic link endpoint accepts all emails — potential for spam/abuse",
        })
    elif any(s == 429 for s, _ in results):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Magic link endpoint is rate-limited",
        })
    elif any(s == 400 for s, _ in results):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Magic link endpoint validates email format",
        })
    else:
        status_codes = [str(s) for s, _ in results if s]
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] Magic link endpoint returned: {', '.join(status_codes) if status_codes else 'errors'}",
        })
    
    return findings
