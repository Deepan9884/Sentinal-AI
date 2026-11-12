"""
SENTINEL-AI Web Launcher.
Starts either the Standalone Cyber-Console (index.html) or the Streamlit Dashboard (app.py).

Usage:
  python run_web.py              # Opens the Standalone Cyber-Console in your default browser
  python run_web.py --streamlit  # Launches the Streamlit Interactive Dashboard
  python run_web.py --serve      # Starts a local HTTP server on port 8000 and opens the browser
"""

import sys
import os
import webbrowser
import argparse

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(CURRENT_DIR, "web")
INDEX_PATH = os.path.join(WEB_DIR, "index.html")
APP_PATH = os.path.join(WEB_DIR, "app.py")


def launch_console():
    print(f"[*] Opening Sentinel Cyber-Console: {INDEX_PATH}")
    webbrowser.open(f"file://{os.path.abspath(INDEX_PATH)}")
    print("[+] Launched successfully in default browser.")


def serve_http(port=8080):
    import http.server
    import socketserver
    
    os.chdir(WEB_DIR)
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), Handler) as httpd:
        url = f"http://localhost:{port}/index.html"
        print(f"[*] Serving Sentinel Web Console at {url}")
        webbrowser.open(url)
        print("[*] Press Ctrl+C to stop server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Server stopped.")


def launch_streamlit():
    import subprocess
    cmd = [sys.executable, "-m", "streamlit", "run", APP_PATH]
    print(f"[*] Launching Streamlit dashboard: {' '.join(cmd)}")
    subprocess.run(cmd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL-AI Frontend Launcher")
    parser.add_argument("--streamlit", action="store_true", help="Launch Streamlit dashboard")
    parser.add_argument("--serve", action="store_true", help="Serve web console over local HTTP server")
    parser.add_argument("--port", type=int, default=8080, help="Port for local HTTP server (default: 8080)")
    
    args = parser.parse_args()
    
    if args.streamlit:
        launch_streamlit()
    elif args.serve:
        serve_http(port=args.port)
    else:
        launch_console()
