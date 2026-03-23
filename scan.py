import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from scanner.client import SupabaseClient
from scanner.cli import parse_args, module_active
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


def run():
    parsed = parse_args()

    url     = parsed["url"]     or getattr(config, "SUPABASE_URL", "")
    key     = parsed["key"]     or getattr(config, "ANON_KEY", "")
    svc_key = parsed["service_key"] or getattr(config, "SERVICE_ROLE_KEY", "") or ""
    quiet   = parsed["quiet"]

    errors = validate(url, key)
    if errors:
        print("\033[91m[ERROR] Fix config.py before running:\033[0m")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    url = url.rstrip("/")
    all_findings = []

    if not quiet:
        print(f"\n\033[1mStarting scan against:\033[0m {url}\n")

    def active(name):
        return module_active(name, parsed)

    if active("jwt"):
        step("Analyzing JWT token(s)", quiet)
        all_findings += jwt_analyzer.analyze(key, label="anon_key")
        if svc_key:
            all_findings += jwt_analyzer.analyze(svc_key, label="service_role_key")

    if active("infra"):
        step("Checking TLS", quiet)
        all_findings += infra_scanner.check_tls(url, label="anon")

    if active("headers"):
        step("Checking HTTP security headers", quiet)
        all_findings += headers_scanner.scan_headers(url, key, label="anon")

    anon = SupabaseClient(url, key)

    if active("infra"):
        step("Probing infrastructure endpoints", quiet)
        all_findings += infra_scanner.scan_endpoints(url, key, label="anon")
        all_findings += infra_scanner.scan_common_files(url, label="anon")

    if active("graphql"):
        step("Testing GraphQL introspection", quiet)
        all_findings += infra_scanner.scan_graphql_introspection(url, key, label="anon")

    if active("tables"):
        step("Discovering and reading tables via schema", quiet)
        all_findings += edge_scanner.scan_postgrest_info(anon, label="anon")
        table_findings, tables = table_scanner.scan_tables(anon, label="anon")
        all_findings += table_findings
    else:
        tables = []

    if active("rpc"):
        step("Probing RPC functions", quiet)
        all_findings += table_scanner.scan_rpc(anon, label="anon")

    if active("bruteforce"):
        step("Brute-forcing common table names", quiet)
        brute_findings, brute_tables = table_scanner.brute_common_tables(anon, label="anon")
        all_findings += brute_findings
        tables = list(set(tables + brute_tables))

    if active("rls"):
        step("Analyzing RLS policies and row exposure", quiet)
        all_findings += rls_analyzer.scan_rls(anon, tables, label="anon")
        all_findings += rls_analyzer.estimate_data_exposure(anon, tables, label="anon")

    if active("idor"):
        step("Testing for IDOR and horizontal privilege escalation", quiet)
        all_findings += idor_scanner.scan_idor(anon, tables, label="anon")
        all_findings += idor_scanner.scan_horizontal_privilege_escalation(anon, tables, label="anon")

    if active("injection"):
        step("Testing PostgREST injection vectors", quiet)
        all_findings += injection_scanner.scan_injections(anon, tables, label="anon")

    if active("mass_assignment"):
        step("Testing mass assignment on exposed tables", quiet)
        all_findings += injection_scanner.scan_mass_assignment(anon, tables, label="anon")

    if active("storage"):
        step("Scanning storage buckets", quiet)
        all_findings += storage_scanner.scan_storage(anon, label="anon")

    if active("auth"):
        step("Probing auth configuration", quiet)
        all_findings += auth_scanner.scan_auth_config(anon, label="anon")
        step("Testing email enumeration", quiet)
        all_findings += auth_scanner.scan_email_enumeration(anon, label="anon")
        step("Probing auth endpoints and brute-force protection", quiet)
        all_findings += auth_scanner.scan_auth_endpoints(anon, label="anon")

    if active("magic_link"):
        step("Testing magic link endpoint", quiet)
        all_findings += auth_scanner.scan_magic_link(anon, label="anon")

    if active("edges"):
        step("Probing edge functions", quiet)
        all_findings += edge_scanner.scan_edge_functions(anon, label="anon")

    if active("realtime"):
        step("Checking realtime endpoint", quiet)
        all_findings += edge_scanner.scan_realtime(anon, label="anon")

    if svc_key:
        if not quiet:
            print(f"\n  \033[93m→\033[0m Re-scanning with service role key...")
        svc = SupabaseClient(url, svc_key)
        if active("tables"):
            svc_table_findings, _ = table_scanner.scan_tables(svc, label="service_role")
            all_findings += svc_table_findings
        if active("storage"):
            all_findings += storage_scanner.scan_storage(svc, label="service_role")
        if active("auth"):
            all_findings += auth_scanner.scan_auth_endpoints(svc, label="service_role")

    reporter.print_findings(all_findings, url)
    scoring.print_score_card(all_findings)
    score_data = scoring.score_to_dict(all_findings)

    saved = []
    if not parsed["no_json"]:
        saved.append(("JSON    ", reporter.save_json(all_findings, url, score_data=score_data)))
    if not parsed["no_md"]:
        saved.append(("Markdown", reporter.save_markdown(all_findings, url)))
    if not parsed["no_html"]:
        saved.append(("HTML    ", reporter.save_html(all_findings, url)))

    if saved and not quiet:
        print("  Reports saved:")
        for fmt, path in saved:
            print(f"    {fmt} → {path}")
        print()


if __name__ == "__main__":
    run()
