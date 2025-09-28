#!/usr/bin/env python3
"""
webview_helper.py
Small helper process that creates a pywebview window. Accepts a single URL in argv.
Usage: python webview_helper.py "http://1.2.3.4"
"""

import sys
import webview
import signal

def main():
    # allow ctrl-c to close
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    url = "about:blank"
    if len(sys.argv) > 1:
        url = sys.argv[1]

    # on some platforms you may choose a specific GUI backend, but default is OK.
    # Create a single window; webview.start() must be called from the main thread (this is main).
    try:
        w = webview.create_window(f"Embedded Browser — {url}", url, width=1024, height=768)
        webview.start()  # blocks until window closes
    except Exception as e:
        # If webview fails, print error and exit so caller can fallback to system browser.
        print("webview helper error:", e, file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
