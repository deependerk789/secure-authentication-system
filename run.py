
"""Development entry point.

Run locally with: python run.py
For production, use a WSGI server configured for app:create_app().
"""

from __future__ import annotations

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in {
        "1", "true", "yes", "on"
    }

    app.run(
        host=host,
        port=port,
        debug=debug,
    )
