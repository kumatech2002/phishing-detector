"""
app.py — Flask application factory for the Phishing Detector.
"""
import os
import sys
import logging
from pathlib import Path

_BACKEND_DIR = Path(__file__).parent
_PROJECT_DIR = _BACKEND_DIR.parent
sys.path.insert(0, str(_PROJECT_DIR))

from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from backend.config import config
from backend.api.routes import api_bp
from backend.db.database import init_db

_IS_VERCEL = bool(os.environ.get("VERCEL"))
_LOG_DIR = Path("/tmp/logs") if _IS_VERCEL else config.LOGS_DIR
_LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_LOG_DIR / "app.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)

_FRONTEND_DIR = _PROJECT_DIR / "frontend"


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder=str(_FRONTEND_DIR),
        static_url_path="",
    )

    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["DEBUG"] = not config.is_production

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[config.RATE_LIMIT],
        storage_uri="memory://",
    )
    limiter.limit(config.RATE_LIMIT)(api_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if config.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    app.register_blueprint(api_bp)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_frontend(path):
        target = _FRONTEND_DIR / path
        if path and target.exists() and target.is_file():
            return send_from_directory(str(_FRONTEND_DIR), path)
        return send_from_directory(str(_FRONTEND_DIR), "index.html")

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"ok": False, "error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"ok": False, "error": "Method not allowed"}), 405

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({"ok": False, "error": "Rate limit exceeded. Please wait before retrying."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        log.exception("Unhandled 500 error")
        return jsonify({"ok": False, "error": "Internal server error"}), 500

    with app.app_context():
        init_db()
        log.info("Database ready.")

    try:
        from backend.ml.predict import _load_artifacts
        _load_artifacts()
        log.info("Model pre-loaded successfully.")
    except FileNotFoundError:
        log.warning(
            "Model file not found — run 'python backend/ml/train.py' to train it first."
        )
    except Exception as exc:
        log.warning("Could not pre-load model: %s", exc)

    log.info("Phishing Detector app created (env=%s)", config.FLASK_ENV)
    return app


if __name__ == "__main__":
    application = create_app()
    log.info("Starting server on http://127.0.0.1:5001")
    application.run(host="127.0.0.1", port=5001, debug=not config.is_production)
