"""SecureAuth - a small, hardened Flask authentication service."""

from __future__ import annotations

from pathlib import Path
from dotenv import load_dotenv
from flask import Flask
from flask_wtf.csrf import CSRFProtect

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

from .config import build_config
from .db import close_db, init_db

__all__ = ["create_app"]

csrf = CSRFProtect()


def create_app(overrides: dict | None = None) -> Flask:
    """Application factory."""
    app = Flask(
        __name__,
        static_folder="static",
        static_url_path="/static",
        template_folder="templates",
    )

    config = build_config()
    if overrides:
        config.update(overrides)

    app.config.update(config)
    app.permanent_session_lifetime = config["PERMANENT_SESSION_LIFETIME"]

    csrf.init_app(app)
    app.teardown_appcontext(close_db)

    from .routes import bp as web_bp

    app.register_blueprint(web_bp)
    init_db(app)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy",
                                    "geolocation=(), microphone=(), camera=(), payment=()")
        if app.config.get("PRODUCTION"):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if response.mimetype == "text/html":
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.errorhandler(404)
    def not_found(_error):
        from flask import render_template

        return render_template("error.html", code=404, title="Page not found",
                               message="That page does not exist."), 404

    @app.errorhandler(413)
    def too_large(_error):
        from flask import render_template

        return render_template("error.html", code=413, title="Request too large",
                               message="That submission was too large to process."), 413

    @app.errorhandler(500)
    def server_error(_error):
        from flask import render_template

        return render_template("error.html", code=500, title="Something went wrong",
                               message="The server could not complete the request."), 500

    return app
