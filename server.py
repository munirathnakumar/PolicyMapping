#!/usr/bin/env python3
"""
server.py  —  SSPM Policy Mapper API + UI server
Serves index.html on / and provides /api/* endpoints for AI mapping.

Usage:
    python server.py                    # port 8080, auto-opens browser
    python server.py --port 5000
    python server.py --mapper ../sspm_v4/sspm_mapper.py
"""

import os, sys, json, csv, io, tempfile, argparse, threading, webbrowser, traceback
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_MAPPER_PATHS = [
    "./sspm_mapper.py",
    "../sspm_v4/sspm_mapper.py",
    "../sspm_mapper.py",
    "../../sspm_mapper.py",
]

def find_mapper(override=None):
    if override and Path(override).exists():
        return str(Path(override).resolve())
    for p in DEFAULT_MAPPER_PATHS:
        if Path(p).exists():
            return str(Path(p).resolve())
    return None

def find_secbert():
    """Look for SecBERT model in common locations near the mapper."""
    candidates = [
        "./secbert_clean", "./secbert_model", "./secbert",
        "../sspm_v4/secbert_clean", "../sspm_v4/secbert_model",
        "../secbert_clean", "../secbert_model",
    ]
    for c in candidates:
        p = Path(c)
        if p.exists() and (p / "config.json").exists():
            return str(p.resolve())
        # Also check cache structure
        for snap in p.rglob("config.json"):
            return str(snap.parent.resolve())
    return None

# ── Mapper runner ──────────────────────────────────────────────────────────────
def run_mapping(controls_csv, policies_csv, app_name, model_mode,
                mapper_path, domain_pairs_json=None):
    """
    Run sspm_mapper.py programmatically and return the report dict.
    model_mode: 'secbert' | 'tfidf' | 'manual'
    """
    if model_mode == 'manual':
        # Return empty mapping — user will assign manually
        return build_empty_report(controls_csv, policies_csv, app_name)

    if not mapper_path or not Path(mapper_path).exists():
        raise FileNotFoundError(
            f"sspm_mapper.py not found. "
            f"Pass --mapper /path/to/sspm_mapper.py when starting server.py"
        )

    mapper_dir = str(Path(mapper_path).parent)

    # Add mapper directory to Python path so imports work
    if mapper_dir not in sys.path:
        sys.path.insert(0, mapper_dir)

    # Write temp files
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as fc:
        fc.write(controls_csv); ctrl_path = fc.name
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as fp:
        fp.write(policies_csv); pol_path = fp.name

    try:
        # Import and use mapper directly
        import importlib.util
        spec = importlib.util.spec_from_file_location("sspm_mapper", mapper_path)
        mod  = importlib.util.module_from_spec(spec)

        # Override model path based on mode
        if model_mode == 'tfidf':
            # Force TF-IDF by temporarily making model path invalid
            os.environ['SSPM_FORCE_TFIDF'] = '1'
        else:
            os.environ.pop('SSPM_FORCE_TFIDF', None)
            secbert = find_secbert()
            if secbert:
                # Inject model path into the module before loading
                os.environ['SSPM_MODEL_PATH'] = secbert

        spec.loader.exec_module(mod)

        # Patch model if needed
        if model_mode == 'tfidf' and hasattr(mod, 'SSPMMapper'):
            # Force tfidf encoder
            orig_load = mod.SecBERTEncoder._load
            def tfidf_load(self):
                self.mode = 'tfidf'
            mod.SecBERTEncoder._load = tfidf_load

        elif model_mode == 'secbert' and hasattr(mod, 'SecBERTEncoder'):
            secbert = find_secbert()
            if secbert:
                mod.SECBERT_MODEL_PATH = secbert

        # Apply domain pairs if provided
        if domain_pairs_json and hasattr(mod, 'DOMAIN_PAIRS'):
            try:
                dp = json.loads(domain_pairs_json)
                mod.DOMAIN_PAIRS.clear()
                mod.DOMAIN_PAIRS.update(dp)
            except Exception:
                pass

        # Run mapper
        mapper = mod.SSPMMapper(model_path=(find_secbert() if model_mode=='secbert' else None))
        mapper.load_controls(ctrl_path)
        mapper.load_policies(pol_path, app=app_name)
        report = mapper.run()

        return report

    finally:
        os.unlink(ctrl_path)
        os.unlink(pol_path)
        os.environ.pop('SSPM_FORCE_TFIDF', None)
        os.environ.pop('SSPM_MODEL_PATH', None)


def build_empty_report(controls_csv, policies_csv, app_name):
    """Parse CSVs and return a report with no mappings (manual mode)."""
    def parse(text):
        text = text.lstrip('\ufeff')
        reader = csv.DictReader(io.StringIO(text))
        return list(reader)

    ctrl_rows = parse(controls_csv)
    pol_rows  = parse(policies_csv)

    def norm_ctrl(r, i):
        return {
            "control_id":   r.get("control_id") or r.get("id") or r.get("ref") or f"CTR-{i+1:03d}",
            "control_text": r.get("control_text") or r.get("control") or r.get("requirement") or "",
            "domain":       r.get("domain") or r.get("security_domain") or "General",
            "framework":    r.get("framework") or r.get("standard") or "",
        }

    def norm_pol(r, i):
        return {
            "policy_id":       r.get("policy_id") or r.get("id") or r.get("ref") or f"POL-{i+1:03d}",
            "policy_name":     r.get("policy_name") or r.get("policy") or r.get("name") or "",
            "policy_category": r.get("category") or r.get("type") or "",
            "description":     r.get("description") or r.get("desc") or "",
        }

    controls = [norm_ctrl(r, i) for i, r in enumerate(ctrl_rows) if r.get("control_text") or r.get("control")]
    orphans  = [norm_pol(r, i)  for i, r in enumerate(pol_rows)  if r.get("policy_name") or r.get("policy")]

    return {
        "app": app_name,
        "summary": {
            "total_controls": len(controls), "total_policies": len(orphans),
            "covered_controls": 0, "uncovered_controls": len(controls),
            "orphan_policies": len(orphans),
            "full_matches": 0, "partial_matches": 0, "indirect_matches": 0,
        },
        "domain_summary": [],
        "control_mappings": [
            {"control_id": c["control_id"], "control_text": c["control_text"],
             "domain": c["domain"], "framework": c["framework"],
             "is_covered": False, "matches": []}
            for c in controls
        ],
        "orphan_policies": orphans,
        "relationships": {"one_to_one": [], "one_to_many": [], "many_to_one": [], "many_to_many": []},
    }


# ── HTTP Handler ───────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):

    MAPPER_PATH = None  # set by main()

    def log_message(self, fmt, *args):
        code = args[1] if len(args) > 1 else ''
        if code not in ('200', '304', '304'):
            super().log_message(fmt, *args)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path

        if path in ('/', '/index.html'):
            self._serve_file('index.html', 'text/html; charset=utf-8')
        elif path.endswith('.js'):
            self._serve_file(path.lstrip('/'), 'application/javascript')
        elif path.endswith('.css'):
            self._serve_file(path.lstrip('/'), 'text/css')
        elif path == '/api/status':
            self._json({
                "status": "ok",
                "mapper_found": bool(Handler.MAPPER_PATH),
                "mapper_path":  Handler.MAPPER_PATH or "not found",
                "secbert_path": find_secbert() or "not found",
                "secbert_ready": bool(find_secbert()),
            })
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path

        if path == '/api/map':
            self._handle_map()
        else:
            self.send_error(404)

    def _handle_map(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length)
        try:
            data = json.loads(body)
        except Exception:
            self._json({"error": "Invalid JSON body"}, 400)
            return

        controls_csv    = data.get("controls_csv", "")
        policies_csv    = data.get("policies_csv", "")
        app_name        = data.get("app_name", "App")
        model_mode      = data.get("model_mode", "secbert")   # secbert | tfidf | manual
        domain_pairs    = data.get("domain_pairs", None)

        if not controls_csv or not policies_csv:
            self._json({"error": "controls_csv and policies_csv are required"}, 400)
            return

        try:
            report = run_mapping(
                controls_csv, policies_csv, app_name, model_mode,
                Handler.MAPPER_PATH, domain_pairs
            )
            self._json({"ok": True, "report": report})
        except Exception as e:
            tb = traceback.format_exc()
            print(f"\n[ERROR] Mapping failed:\n{tb}")
            self._json({"error": str(e), "detail": tb}, 500)

    def _json(self, data, code=200):
        body = json.dumps(data, default=str).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, filepath, content_type):
        p = Path(__file__).parent / filepath
        if not p.exists():
            self.send_error(404)
            return
        data = p.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description='SSPM Policy Mapper API + UI Server')
    ap.add_argument('--port',   type=int, default=8080)
    ap.add_argument('--mapper', default=None, help='Path to sspm_mapper.py')
    ap.add_argument('--no-browser', action='store_true')
    args = ap.parse_args()

    os.chdir(Path(__file__).parent)

    mapper = find_mapper(args.mapper)
    Handler.MAPPER_PATH = mapper
    secbert = find_secbert()

    url = f'http://localhost:{args.port}'
    print(f'\n  ◈  SSPM Policy Mapper\n')
    print(f'  UI     : {url}')
    print(f'  Mapper : {mapper or "⚠  NOT FOUND — only manual mode available"}')
    print(f'  SecBERT: {secbert or "⚠  NOT FOUND — TF-IDF will be used"}')
    print(f'\n  Ctrl+C to stop\n')

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    httpd = HTTPServer(('', args.port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\n  Stopped.')
        sys.exit(0)

if __name__ == '__main__':
    main()
