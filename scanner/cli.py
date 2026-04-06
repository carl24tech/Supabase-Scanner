import sys
import re
from typing import Dict, Set, List, Optional, Any

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

MODULE_DEPENDENCIES = {
    "idor": ["tables"],
    "rls": ["tables"],
    "injection": ["tables"],
    "mass_assignment": ["tables"],
}

MODULE_CATEGORIES = {
    "critical": ["jwt", "storage", "auth", "rls", "idor"],
    "safe": ["headers", "infra", "graphql"],
    "data": ["tables", "bruteforce", "storage"],
    "default": ["jwt", "headers", "tables", "rls", "storage", "auth", "infra"],
    "all": AVAILABLE_MODULES,
}

MODULE_ALIASES = {
    "auth": ["authentication", "email_enumeration"],
    "bruteforce": ["brute", "table_brute"],
    "edges": ["edge_functions", "functions"],
    "infra": ["infrastructure", "tls"],
}

USAGE = f"""
Supabase Scanner — Security Scanner for Supabase Projects

Usage:
  python scan.py [options]

Options:
  --url URL            Supabase project URL (overrides config.py)
  --key KEY            Anon API key (overrides config.py)
  --service-key KEY    Service role key (overrides config.py)
  --modules M1,M2,...  Run specific modules or categories
  --skip M1,M2,...     Skip specific modules
  --category CAT       Run module category: default, critical, safe, data, all
  --no-html            Skip HTML report generation
  --no-json            Skip JSON report generation
  --no-md              Skip Markdown report generation
  --quiet              Suppress step-by-step output
  --help               Show this message

Module Categories:
  default  - Standard modules for typical scan
  critical - High-risk modules (jwt,storage,auth,rls,idor)
  safe     - Low-risk modules (headers,infra,graphql)
  data     - Data discovery modules (tables,bruteforce,storage)
  all      - All available modules

Available Modules:
  {', '.join(AVAILABLE_MODULES)}

Examples:
  python scan.py
  python scan.py --url https://xyz.supabase.co --key eyJ...
  python scan.py --modules jwt,tables,storage
  python scan.py --category critical
  python scan.py --skip bruteforce,magic_link --category default
"""

def validate_url(url: str) -> bool:
    if not url:
        return False
    pattern = r'^https?:\/\/[a-zA-Z0-9][a-zA-Z0-9-]*\.supabase\.co$'
    if re.match(pattern, url):
        return True
    return url.startswith(('http://', 'https://')) and 'supabase' in url.lower()

def validate_key(key: str) -> bool:
    if not key:
        return False
    return len(key) > 20 and any(c in key for c in ['.', 'eyJ'])

def normalize_module_name(name: str) -> str:
    name_lower = name.lower().strip()
    for canonical, aliases in MODULE_ALIASES.items():
        if name_lower == canonical or name_lower in aliases:
            return canonical
    if name_lower in AVAILABLE_MODULES:
        return name_lower
    return None

def resolve_modules_from_category(category: str) -> Set[str]:
    category_lower = category.lower()
    if category_lower in MODULE_CATEGORIES:
        return set(MODULE_CATEGORIES[category_lower])
    return set()

def resolve_dependencies(modules: Set[str]) -> Set[str]:
    resolved = set(modules)
    changed = True
    while changed:
        changed = False
        for module in list(resolved):
            if module in MODULE_DEPENDENCIES:
                for dep in MODULE_DEPENDENCIES[module]:
                    if dep not in resolved:
                        resolved.add(dep)
                        changed = True
    return resolved

def parse_args(argv: Optional[List[str]] = None) -> Dict[str, Any]:
    if argv is None:
        argv = sys.argv[1:]
    
    parsed = {
        "url": None,
        "key": None,
        "service_key": None,
        "modules": None,
        "skip": set(),
        "category": None,
        "no_html": False,
        "no_json": False,
        "no_md": False,
        "quiet": False,
        "active_modules": set(),
    }
    
    i = 0
    while i < len(argv):
        arg = argv[i]
        
        if arg in ("--help", "-h"):
            print(USAGE)
            sys.exit(0)
        
        elif arg == "--url" and i + 1 < len(argv):
            parsed["url"] = argv[i + 1]
            i += 2
        
        elif arg == "--key" and i + 1 < len(argv):
            parsed["key"] = argv[i + 1]
            i += 2
        
        elif arg == "--service-key" and i + 1 < len(argv):
            parsed["service_key"] = argv[i + 1]
            i += 2
        
        elif arg == "--modules" and i + 1 < len(argv):
            raw = [m.strip() for m in argv[i + 1].split(",") if m.strip()]
            normalized = []
            for m in raw:
                norm = normalize_module_name(m)
                if norm:
                    normalized.append(norm)
                else:
                    print(f"[ERROR] Unknown module: {m}")
                    print(f"Available: {', '.join(AVAILABLE_MODULES)}")
                    sys.exit(1)
            parsed["modules"] = set(normalized)
            i += 2
        
        elif arg == "--skip" and i + 1 < len(argv):
            raw = [m.strip() for m in argv[i + 1].split(",") if m.strip()]
            normalized = set()
            for m in raw:
                norm = normalize_module_name(m)
                if norm:
                    normalized.add(norm)
                else:
                    print(f"[WARNING] Unknown module in skip list: {m}")
            parsed["skip"] = normalized
            i += 2
        
        elif arg == "--category" and i + 1 < len(argv):
            category = argv[i + 1].lower()
            if category in MODULE_CATEGORIES:
                parsed["category"] = category
            else:
                print(f"[ERROR] Unknown category: {category}")
                print(f"Available categories: {', '.join(MODULE_CATEGORIES.keys())}")
                sys.exit(1)
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
    
    if parsed["url"] and not validate_url(parsed["url"]):
        print(f"[WARNING] URL format may be invalid: {parsed['url']}")
    
    if parsed["key"] and not validate_key(parsed["key"]):
        print(f"[WARNING] API key format may be invalid (too short or wrong structure)")
    
    if parsed["modules"] and parsed["category"]:
        print(f"[WARNING] Both --modules and --category specified. Using --modules.")
    
    if parsed["category"] and not parsed["modules"]:
        parsed["modules"] = resolve_modules_from_category(parsed["category"])
    
    if parsed["modules"] is None:
        parsed["modules"] = resolve_modules_from_category("default")
    
    active = set(parsed["modules"]) - parsed["skip"]
    active = resolve_dependencies(active)
    
    if not active:
        print("[ERROR] No modules selected to run after applying filters.")
        print(f"Modules specified: {parsed['modules']}")
        print(f"Modules skipped: {parsed['skip']}")
        sys.exit(1)
    
    parsed["active_modules"] = active
    
    return parsed

def module_active(name: str, parsed: Dict[str, Any]) -> bool:
    return name in parsed.get("active_modules", set())
