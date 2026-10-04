"""
app.py
------
Flask application entry point.

Serves both the REST API (/api/*) and the SOC dashboard (/, /app.js, /styles.css).

Run:
    python -m backend.app
"""

from __future__ import annotations

from flask import Flask, send_from_directory

from backend.database import init_db
from backend.routes import api, seed_rules
from config import API_DEBUG, API_HOST, API_PORT, FRONTEND_DIR


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")

    init_db(app)
    app.register_blueprint(api)

    with app.app_context():
        seed_rules()

    # ---------------- Frontend ----------------
    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "Network IDS Simulation"}

    # ---------------- Error handlers ----------------
    @app.errorhandler(404)
    def not_found(_):
        return {"error": "Resource not found", "status": 404}, 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return {"error": "Method not allowed", "status": 405}, 405

    @app.errorhandler(500)
    def server_error(_):
        return {"error": "Internal server error", "status": 500}, 500

    return app


app = create_app()


if __name__ == "__main__":
    print(f"[*] IDS API + Dashboard -> http://{API_HOST}:{API_PORT}")
    app.run(host=API_HOST, port=API_PORT, debug=API_DEBUG)