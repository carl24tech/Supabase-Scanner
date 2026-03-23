import sys


AVAILABLE_MODULES = [
    "jwt",
    "headers",
    "tables",
    "rpc",
    "bruteforce",
    "injection",
    "mass_assignment",
    "rls",
    "idor",
    "storage",
    "auth",
    "magic_link",
    "edges",
    "realtime",
    "graphql",
    "infra",
    "files",
]

USAGE = f"""
Supabase Scanner — github.com/carl24tech/Supabase-Scanner

Usage:
  python scan.py [options]

Options:
  --url URL            Supabase project URL (overrides config.py)
  --key KEY            Anon API key (overrides config.py)
  --service-key KEY    Service role key (overrides config.py)
  --modules M1,M2,...  Run only specific modules (comma-separated)
  --skip M1,M2,...     Skip specific modules
  --no-html            Skip HTML report generation
  --no-json            Skip JSON report generation
  --no-md              Skip Markdown report generation
  --quiet              Suppress step-by-step output
  --help               Show this message

Available modules:
  {', '.join(AVAILABLE_MODULES)}

Examples:
  python scan.py
  python scan.py --url https://xyz.supabase.co --key eyJ...
  python scan.py --modules jwt,tables,storage
  python scan.py --skip bruteforce,magic_link
"""


def parse_args(argv=None):
    args = argv if argv is not None else sys.argv[1:]

    parsed = {
        "url": None,
        "key": None,
        "service_key": None,
        "modules": None,
        "skip": set(),
        "no_html": False,
        "no_json": False,
        "no_md": False,
        "quiet": False,
    }

    i = 0
    while i < len(args):
        arg = args[i]

        if arg in ("--help", "-h"):
            print(USAGE)
            sys.exit(0)

        elif arg == "--url" and i + 1 < len(args):
            parsed["url"] = args[i + 1]
            i += 2

        elif arg == "--key" and i + 1 < len(args):
            parsed["key"] = args[i + 1]
            i += 2

        elif arg == "--service-key" and i + 1 < len(args):
            parsed["service_key"] = args[i + 1]
            i += 2

        elif arg == "--modules" and i + 1 < len(args):
            raw = [m.strip().lower() for m in args[i + 1].split(",") if m.strip()]
            unknown = [m for m in raw if m not in AVAILABLE_MODULES]
            if unknown:
                print(f"[ERROR] Unknown module(s): {', '.join(unknown)}")
                print(f"Available: {', '.join(AVAILABLE_MODULES)}")
                sys.exit(1)
            parsed["modules"] = set(raw)
            i += 2

        elif arg == "--skip" and i + 1 < len(args):
            raw = [m.strip().lower() for m in args[i + 1].split(",") if m.strip()]
            parsed["skip"] = set(raw)
            i += 2

        elif arg == "--no-html":
            parsed["no_html"] = True
            i += 1

        elif arg == "--no-json":
            parsed["no_json"] = True
            i += 1

        elif arg == "--no-md":
            parsed["no_md"] = True
            i += 1

        elif arg == "--quiet":
            parsed["quiet"] = True
            i += 1

        else:
            print(f"[ERROR] Unknown argument: {arg}")
            print("Run `python scan.py --help` for usage.")
            sys.exit(1)

    return parsed


def module_active(name, parsed):
    if name in parsed.get("skip", set()):
        return False
    if parsed.get("modules") is None:
        return True
    return name in parsed["modules"]
