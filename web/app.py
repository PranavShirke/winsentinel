"""
WinSentinel - Flask Web Application Factory.

Initializes the application with:
  - CSRF protection via Flask-WTF CSRFProtect.
  - Defense-in-depth security headers (CSP, X-Frame-Options, X-Content-Type-Options).
  - Secure session cookie configurations (HttpOnly, SameSite=Lax, 30-minute timeout).
  - Blueprints for authentication (auth_bp) and dashboard views (views_bp).
"""

from datetime import timedelta
from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect

from config import get_config
from db.database import init_db
from web.security import apply_security_headers
from web.auth import auth_bp
from web.views import views_bp


def create_app() -> Flask:
    """
    Construct, configure, and return the Flask application instance.

    Returns:
        Flask: Fully configured application.
    """
    cfg = get_config()
    init_db()  # idempotent: creates new tables when upgrading an existing database
    app = Flask(__name__)

    # Core Security Settings
    app.config["SECRET_KEY"] = cfg.SECRET_KEY
    app.config["DEBUG"] = False
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # no endpoint needs large request bodies
    app.config["SESSION_COOKIE_HTTPONLY"] = cfg.SESSION_COOKIE_HTTPONLY
    app.config["SESSION_COOKIE_SAMESITE"] = cfg.SESSION_COOKIE_SAMESITE
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=cfg.SESSION_TIMEOUT_MINUTES)

    # Initialize CSRF Protection
    csrf = CSRFProtect(app)

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(views_bp)

    # Attach Defense-in-Depth Security Headers to all responses
    app.after_request(apply_security_headers)

    # Custom Error Handlers
    @app.errorhandler(400)
    def bad_request_error(e):
        from flask import request, jsonify
        if request.path.startswith("/api/") or request.path.startswith("/scan/"):
            return jsonify({"error": "Bad Request / CSRF verification failed."}), 400
        return "<h1>400 Bad Request</h1><p>CSRF verification failed or invalid request.</p>", 400

    @app.errorhandler(405)
    def method_not_allowed_error(e):
        return "<h1>405 Method Not Allowed</h1>", 405

    @app.errorhandler(404)
    def not_found_error(e):
        return "<h1>404 Not Found</h1><p>The requested security resource does not exist.</p>", 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return "<h1>500 Internal Error</h1><p>An unexpected server error occurred.</p>", 500

    return app
