
import urllib.request
import urllib.error
import json


SUPABASE_ENDPOINTS = [
    ("/rest/v1/",                "REST API"),
    ("/auth/v1/",                "Auth API"),
    ("/storage/v1/",             "Storage API"),
    ("/realtime/v1/",            "Realtime API"),
    ("/functions/v1/",           "Edge Functions"),
    ("/graphql/v1",              "GraphQL"),
    ("/pg/v0/query",             "pg Gateway (Supabase internal)"),
    ("/studio/api/platform",     "Studio API"),
    ("/v1/health",               "Health endpoint"),
]

SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]

COMMON_FILES = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/config.json",
    "/api.json",
    "/.git/config",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api/swagger",
]


def _probe(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(512)
            return resp.status, body.decode(errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read(256)
        try:
            return e.code, body.decode(errors="replace"), dict(e.headers)
        except Exception:
            return e.code, "", {}
    except Exception:
        return 0, "", {}


def scan_endpoints(base_url, key, label="anon"):
    findings = []
    base = base_url.rstrip("/")
    auth_headers = {"apikey": key, "Authorization": f"Bearer {key}"}

    for path, name in SUPABASE_ENDPOINTS:
        status, body, headers = _probe(base + path, headers=auth_headers)
        if status == 0:
            continue
        if path == "/graphql/v1" and status == 200:
            findings.append({
                "severity": "MEDIUM",
                "issue": f"[{label}] GraphQL endpoint is active — introspection may expose full schema",
            })
            intr_status, intr_body, _ = _probe(
                base + path,
                headers={**auth_headers, "Content-Type": "application/json"},
            )
        elif path == "/pg/v0/query" and status not in (404, 0):
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] pg gateway responded with {status} — direct SQL query endpoint may be accessible",
            })
        elif status not in (404, 405, 0):
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] {name} at '{path}' is reachable (status {status})",
            })

    return findings


def scan_graphql_introspection(base_url, key, label="anon"):
    findings = []
    base = base_url.rstrip("/")
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    introspection_query = json.dumps({
        "query": "{ __schema { types { name kind fields { name type { name kind } } } } }"
    }).encode()

    req = urllib.request.Request(
        base + "/graphql/v1",
        data=introspection_query,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read()
            try:
                data = json.loads(body)
                if "data" in data and "__schema" in data.get("data", {}):
                    types = data["data"]["__schema"].get("types", [])
                    user_types = [t["name"] for t in types if not t["name"].startswith("__")]
                    findings.append({
                        "severity": "HIGH",
                        "issue": f"[{label}] GraphQL introspection is ENABLED — full schema leaked ({len(user_types)} types): {', '.join(user_types[:10])}",
                    })
                else:
                    findings.append({
                        "severity": "INFO",
                        "issue": f"[{label}] GraphQL introspection returned a response but schema was not exposed",
                    })
            except Exception:
                pass
    except urllib.error.HTTPError as e:
        if e.code == 404:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] GraphQL endpoint not found (404)",
            })
        else:
            findings.append({
                "severity": "INFO",
                "issue": f"[{label}] GraphQL introspection returned {e.code}",
            })
    except Exception:
        pass

    return findings


def scan_common_files(base_url, label="anon"):
    findings = []
    base = base_url.rstrip("/")

    for path in COMMON_FILES:
        status, body, headers = _probe(base + path)
        if status == 200:
            body_lower = body.lower()
            if path == "/.git/config" and "[core]" in body_lower:
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"[{label}] Git repository config exposed at '/.git/config' — source code history may be downloadable",
                })
            elif path in ("/.env",) and any(k in body_lower for k in ("key=", "secret=", "password=", "token=")):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"[{label}] Environment file exposed at '{path}' containing credential-like values",
                })
            elif path in ("/swagger.json", "/openapi.json", "/api.json") and ("{" in body):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": f"[{label}] API specification file accessible at '{path}' — endpoint structure disclosed",
                })
            else:
                findings.append({
                    "severity": "LOW",
                    "issue": f"[{label}] '{path}' returned 200 — review its contents",
                })

    if not any(f["severity"] in ("CRITICAL", "HIGH") for f in findings):
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] No sensitive common files (.env, .git/config, swagger) found at root",
        })

    return findings


def check_tls(base_url, label="anon"):
    findings = []
    if not base_url.startswith("https://"):
        findings.append({
            "severity": "CRITICAL",
            "issue": f"[{label}] SUPABASE_URL does not use HTTPS — all traffic including API keys is transmitted in plaintext",
        })
    else:
        findings.append({
            "severity": "INFO",
            "issue": f"[{label}] HTTPS is in use",
        })
    return findings
