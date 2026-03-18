#!/usr/bin/env python3
"""serve.py — Serves SSPM Policy Mapper UI on http://localhost:8080"""
import http.server, socketserver, webbrowser, argparse, os, sys

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=8080)
    p.add_argument('--no-browser', action='store_true')
    args = p.parse_args()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    class H(http.server.SimpleHTTPRequestHandler):
        def log_message(self, f, *a):
            if a[1] not in ('200','304'): super().log_message(f, *a)
    url = f'http://localhost:{args.port}'
    print(f'\n  ◈  SSPM Policy Mapper UI\n  URL  : {url}\n  Ctrl+C to stop\n')
    if not args.no_browser: webbrowser.open(url)
    with socketserver.TCPServer(('', args.port), H) as s:
        try: s.serve_forever()
        except KeyboardInterrupt: print('\n  Stopped.'); sys.exit(0)

if __name__ == '__main__': main()
