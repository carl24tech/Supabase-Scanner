import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from scanner.client import SupabaseClient
from scanner.cli import parse_args, module_active

try:
    from scanner import (
        jwt_analyzer,
        table_scanner,
        storage_scanner,
        auth_scanner,
        headers_scanner,
        injection_scanner,
        edge_scanner,
        rls_analyzer,
        idor_scanner,
        infra_scanner,
        scoring,
        reporter,
    )
except ImportError as e:
    print(f"\033[91m[ERROR] Failed to import scanner modules: {e}\033[0m")
    sys.exit(1)

def validate(url, key):
    errors = []
    if not url or "your-project-ref" in url:
        errors.append("SUPABASE_URL is not configured")
    if not key or "your-anon-key" in key:
        errors.append("ANON_KEY is not configured")
    return errors

def step(msg, quiet=False):
    if not quiet:
        print(f"  \033[96m→\033[0m {msg}...")

def safe_scan(module_func, *args, **kwargs):
    try:
        return module_func(*args, **kwargs) if module_func else []
    except Exception as e:
        if not kwargs.get('quiet', False):
            print(f"  \033[91m✗\033[0m Scan failed: {str(e)[:100]}")
        return []

def run():
    parsed = parse_args()

    url = parsed.get("url") or getattr(config, "SUPABASE_URL", "")
    key = parsed.get("key") or getattr(config, "ANON_KEY", "")
    svc_key = parsed.get("service_key") or getattr(config, "SERVICE_ROLE_KEY", "") or ""
    quiet = parsed.get("quiet", False)

    errors = validate(url, key)
    if errors:
        print("\033[91m[ERROR] Fix config.py before running:\033[0m")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    url = url.rstrip("/")
    all_findings = []
    discovered_tables = []

    if not quiet:
        print(f"\n\033[1mStarting scan against:\033[0m {url}\n")

    def active(name):
        return module_active(name, parsed)

    if active("jwt"):
        step("Analyzing JWT token(s)", quiet)
        all_findings.extend(safe_scan(jwt_analyzer.analyze, key, label="anon_key", quiet=quiet))
        if svc_key:
            all_findings.extend(safe_scan(jwt_analyzer.analyze, svc_key, label="service_role_key", quiet=quiet))

    if active("infra"):
        step("Checking TLS", quiet)
        all_findings.extend(safe_scan(infra_scanner.check_tls, url, label="anon", quiet=quiet))

    if active("headers"):
        step("Checking HTTP security headers", quiet)
        all_findings.extend(safe_scan(headers_scanner.scan_headers, url, key, label="anon", quiet=quiet))

    anon = SupabaseClient(url, key)

    if active("infra"):
        step("Probing infrastructure endpoints", quiet)
        all_findings.extend(safe_scan(infra_scanner.scan_endpoints, url, key, label="anon", quiet=quiet))
        all_findings.extend(safe_scan(infra_scanner.scan_common_files, url, label="anon", quiet=quiet))

    if active("graphql"):
        step("Testing GraphQL introspection", quiet)
        all_findings.extend(safe_scan(infra_scanner.scan_graphql_introspection, url, key, label="anon", quiet=quiet))

    if active("tables"):
        step("Discovering and reading tables via schema", quiet)
        all_findings.extend(safe_scan(edge_scanner.scan_postgrest_info, anon, label="anon", quiet=quiet))
        table_findings, tables = safe_scan(table_scanner.scan_tables, anon, label="anon", quiet=quiet) or ([], [])
        all_findings.extend(table_findings)
        discovered_tables.extend(tables)

    if active("rpc"):
        step("Probing RPC functions", quiet)
        all_findings.extend(safe_scan(table_scanner.scan_rpc, anon, label="anon", quiet=quiet))

    if active("bruteforce"):
        step("Brute-forcing common table names", quiet)
        brute_findings, brute_tables = safe_scan(table_scanner.brute_common_tables, anon, label="anon", quiet=quiet) or ([], [])
        all_findings.extend(brute_findings)
        discovered_tables = list(set(discovered_tables + brute_tables))

    if active("rls"):
        step("Analyzing RLS policies and row exposure", quiet)
        all_findings.extend(safe_scan(rls_analyzer.scan_rls, anon, discovered_tables, label="anon", quiet=quiet))
        all_findings.extend(safe_scan(rls_analyzer.estimate_data_exposure, anon, discovered_tables, label="anon", quiet=quiet))

    if active("idor"):
        step("Testing for IDOR and horizontal privilege escalation", quiet)
        all_findings.extend(safe_scan(idor_scanner.scan_idor, anon, discovered_tables, label="anon", quiet=quiet))
        all_findings.extend(safe_scan(idor_scanner.scan_horizontal_privilege_escalation, anon, discovered_tables, label="anon", quiet=quiet))

    if active("injection"):
        step("Testing PostgREST injection vectors", quiet)
        all_findings.extend(safe_scan(injection_scanner.scan_injections, anon, discovered_tables, label="anon", quiet=quiet))

    if active("mass_assignment"):
        step("Testing mass assignment on exposed tables", quiet)
        all_findings.extend(safe_scan(injection_scanner.scan_mass_assignment, anon, discovered_tables, label="anon", quiet=quiet))

    if active("storage"):
        step("Scanning storage buckets", quiet)
        all_findings.extend(safe_scan(storage_scanner.scan_storage, anon, label="anon", quiet=quiet))

    if active("auth"):
        step("Probing auth configuration", quiet)
        all_findings.extend(safe_scan(auth_scanner.scan_auth_config, anon, label="anon", quiet=quiet))
        step("Testing email enumeration", quiet)
        all_findings.extend(safe_scan(auth_scanner.scan_email_enumeration, anon, label="anon", quiet=quiet))
        step("Probing auth endpoints and brute-force protection", quiet)
        all_findings.extend(safe_scan(auth_scanner.scan_auth_endpoints, anon, label="anon", quiet=quiet))

    if active("magic_link"):
        step("Testing magic link endpoint", quiet)
        all_findings.extend(safe_scan(auth_scanner.scan_magic_link, anon, label="anon", quiet=quiet))

    if active("edges"):
        step("Probing edge functions", quiet)
        all_findings.extend(safe_scan(edge_scanner.scan_edge_functions, anon, label="anon", quiet=quiet))

    if active("realtime"):
        step("Checking realtime endpoint", quiet)
        all_findings.extend(safe_scan(edge_scanner.scan_realtime, anon, label="anon", quiet=quiet))

    if svc_key:
        if not quiet:
            print(f"\n  \033[93m→\033[0m Re-scanning with service role key...")
        svc = SupabaseClient(url, svc_key)
        if active("tables"):
            svc_table_findings, _ = safe_scan(table_scanner.scan_tables, svc, label="service_role", quiet=quiet) or ([], [])
            all_findings.extend(svc_table_findings)
        if active("storage"):
            all_findings.extend(safe_scan(storage_scanner.scan_storage, svc, label="service_role", quiet=quiet))
        if active("auth"):
            all_findings.extend(safe_scan(auth_scanner.scan_auth_endpoints, svc, label="service_role", quiet=quiet))

    reporter.print_findings(all_findings, url)
    scoring.print_score_card(all_findings)
    score_data = scoring.score_to_dict(all_findings)

    saved = []
    if not parsed.get("no_json", False):
        saved.append(("JSON    ", reporter.save_json(all_findings, url, score_data=score_data)))
    if not parsed.get("no_md", False):
        saved.append(("Markdown", reporter.save_markdown(all_findings, url)))
    if not parsed.get("no_html", False):
        saved.append(("HTML    ", reporter.save_html(all_findings, url)))

    if saved and not quiet:
        print("  Reports saved:")
        for fmt, path in saved:
            print(f"    {fmt} → {path}")
        print()

if __name__ == "__main__":
    run()
