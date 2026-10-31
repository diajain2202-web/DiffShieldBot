"""
run.py - DiffShield local server runner.
"""

from __future__ import annotations

import os
import uvicorn


def main():
    host = os.getenv("DIFFSHIELD_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", os.getenv("DIFFSHIELD_PORT", "8000")))
    reload = os.getenv("DIFFSHIELD_RELOAD", "1") == "1"

    print(f"Starting DiffShield GitHub App on http://{host}:{port}")
    uvicorn.run("app.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()

