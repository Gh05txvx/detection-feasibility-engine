"""The local web server (docs/BLUEPRINT.md 8.1-8.2).

    python -m engine.web.serve

**Binds to 127.0.0.1 and nothing else.** That is what enforces the
confidentiality constraint at the network level rather than by good intentions:
on 0.0.0.0 any device on the same network could read a client's raw logs out of
this tool. The host is not configurable, deliberately.

No authentication either, for the same reason it needs none: the socket is not
reachable from another machine, and this is a single-user local tool.

If the port is already taken, the assumption is that another instance is already
running, so the browser is pointed at it instead of failing to start a second
one (BLUEPRINT 8.1).
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import webbrowser
from typing import Sequence

# Loopback only. Not a setting, not an argument.
HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def create_app():
    """Build the FastAPI application."""
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles

    from engine.web.routes import STATIC_DIR, router

    app = FastAPI(
        title="Detection Feasibility Engine",
        description="Local, offline. Nothing here is deployed to Elastic.",
        docs_url=None,
        redoc_url=None,
    )
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(router)
    return app


def port_is_free(port: int, host: str = HOST) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError:
            return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port to listen on (default {DEFAULT_PORT})")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    args = parser.parse_args(argv)

    url = f"http://{HOST}:{args.port}"

    if not port_is_free(args.port):
        print(f"Port {args.port} is already in use; assuming the engine is already running.")
        if args.no_browser:
            print(f"It is at {url}")
        else:
            print(f"Opening {url}")
            webbrowser.open(url)
        return 0

    from engine.storage import db

    db.init_db()

    if not args.no_browser:
        # Give uvicorn a moment to bind before the browser asks for the page.
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()

    print(f"Detection Feasibility Engine: {url}")
    print("Local only. Press Ctrl+C to stop.")

    import uvicorn

    uvicorn.run(create_app(), host=HOST, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
