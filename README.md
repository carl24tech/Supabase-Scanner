# Supabase Scanner

Scans a Supabase project for security misconfigurations and data leakages across tables, storage, auth, edge functions, RLS policies, IDOR, injection vectors, GraphQL, and HTTP headers. Every scan produces a risk score and saves reports to `reports/` as JSON, Markdown, and HTML.

---

## Windows Terminal

```bash
git clone https://github.com/carl24tech/Supabase-Scanner.git
cd Supabase-Scanner
```

Open `config.py` and fill in your project details:

```python
SUPABASE_URL = "https://your-project-ref.supabase.co"
ANON_KEY = "your-anon-key-here"
SERVICE_ROLE_KEY = ""  # optional — add if you want a privileged scan pass
```

Run the scanner:

```bash
python scan.py
```

---

## VS Code

1. Go to [github.com/carl24tech/Supabase-Scanner](https://github.com/carl24tech/Supabase-Scanner) and click **Fork**.

2. Clone your fork:
   ```bash
   git clone https://github.com/{your-github-username}/Supabase-Scanner.git
   ```

3. Open in VS Code:
   ```bash
   cd Supabase-Scanner
   code .
   ```

4. Open `config.py` and update it with your Supabase project URL and keys.

5. Open the integrated terminal with `Ctrl + `` ` `` and run:
   ```bash
   python scan.py
   ```

6. Results print to the terminal with a risk score. Full reports are written to `reports/` as `.json`, `.md`, and `.html`.

---

## CLI Options

```
python scan.py --help
python scan.py --url https://xyz.supabase.co --key eyJ...
python scan.py --modules jwt,tables,storage
python scan.py --skip bruteforce,magic_link
python scan.py --no-html --quiet
```

| Flag | Description |
|---|---|
| `--url URL` | Override SUPABASE_URL from config.py |
| `--key KEY` | Override ANON_KEY from config.py |
| `--service-key KEY` | Override SERVICE_ROLE_KEY from config.py |
| `--modules M1,M2` | Run only specific modules |
| `--skip M1,M2` | Skip specific modules |
| `--no-html` | Skip HTML report |
| `--no-json` | Skip JSON report |
| `--no-md` | Skip Markdown report |
| `--quiet` | Suppress step output |

---

## What It Checks

| Module | Checks |
|---|---|
| `jwt` | Algorithm, role, expiry, project metadata in payload |
| `headers` | HSTS, CSP, CORS wildcard, X-Frame-Options, server leakage |
| `tables` | Publicly readable tables, sensitive column names, write/update/delete access |
| `rpc` | Exposed RPC functions, unauthenticated execution |
| `bruteforce` | 30+ common table names probed even if not in schema |
| `rls` | RLS policy analysis, pg_catalog exposure, row count estimation |
| `idor` | Insecure direct object reference, horizontal privilege escalation |
| `injection` | PostgREST filter/order/select injection probes |
| `mass_assignment` | Privileged field injection (is_admin, role, balance, etc.) |
| `storage` | Public buckets, file listing, sensitive filenames, MIME restrictions |
| `auth` | Open signup, auto-confirm, admin endpoint, brute-force protection |
| `magic_link` | Magic link spam/abuse potential |
| `edges` | 30+ common edge function names, unauthenticated access |
| `realtime` | Open realtime broadcast channels |
| `graphql` | Introspection enabled, full schema leakage |
| `infra` | Active Supabase endpoints, common file probing (.env, .git/config, swagger) |

---

## Requirements

- Python 3.8+
- No external packages




![Supabase Security Scanner](https://files.catbox.moe/vvzkow.png)
