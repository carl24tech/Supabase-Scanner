
import urllib.request
import urllib.error


REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set — connections may be downgraded to HTTP",
    "x-content-type-options": "Missing X-Content-Type-Options: nosniff — MIME sniffing attacks possible",
    "x-frame-options": "Missing X-Frame-Options — clickjacking protection not in place",
    "content-security-policy": "No Content-Security-Policy header",
    "referrer-policy": "Missing Referrer-Policy — referrer data may leak to third parties",
}

INFO_LEAK_HEADERS = ["x-powered-by", "server", "x-aspnet-version", "x-runtime", "x-generator"]


def scan_headers(base_url, key, label="anon"):
    findings = []
    url = f"{base_url.rstrip('/')}/rest/v1/"
    req = urllib.request.Request(
        url,
        headers={"apikey": key, "Authorization": f"Bearer {key}"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_headers = dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw_headers = dict(e.headers)
    except Exception as ex:
        findings.append({"severity": "INFO", "issue": f"[{label}] Could not retrieve headers: {ex}"})
        return findings

    headers = {k.lower(): v for k, v in raw_headers.items()}

    for header, message in REQUIRED_SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({"severity": "LOW", "issue": f"[{label}] {message}"})

    hsts = headers.get("strict-transport-security", "")
    if hsts:
        if "max-age=0" in hsts:
            findings.append({"severity": "MEDIUM", "issue": f"[{label}] HSTS max-age is 0 — HSTS is effectively disabled"})
        elif "includeSubDomains" not in hsts:
            findings.append({"severity": "LOW", "issue": f"[{label}] HSTS does not include subdomains"})

    cors = headers.get("access-control-allow-origin", "")
    if cors == "*":
        findings.append({
            "severity": "MEDIUM",
            "issue": f"[{label}] CORS is open (Access-Control-Allow-Origin: *) — any origin can make requests to this API",
        })
    elif cors:
        findings.append({"severity": "INFO", "issue": f"[{label}] CORS restricted to: {cors}"})

    cors_methods = headers.get("access-control-allow-methods", "")
    if cors_methods:
        dangerous = [m for m in ["DELETE", "PATCH", "PUT"] if m in cors_methods.upper()]
        if dangerous and cors == "*":
            findings.append({
                "severity": "HIGH",
                "issue": f"[{label}] CORS wildcard combined with destructive methods ({', '.join(dangerous)}) — cross-origin writes/deletes may be possible",
            })

    for header in INFO_LEAK_HEADERS:
        if header in headers:
            findings.append({
                "severity": "LOW",
                "issue": f"[{label}] Server leaks technology via header '{header}: {headers[header]}'",
            })

    server = headers.get("server", "")
    if server:
        findings.append({
            "severity": "LOW",
            "issue": f"[{label}] Server header reveals: '{server}'",
        })

    return findings
