"""
database.py
-----------
SQLAlchemy database initialisation.

We use SQLite because it needs zero setup and is perfect for a student
project. The same models work with PostgreSQL by changing DATABASE_URL.
"""

from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy

from config import DATABASE_URL

db = SQLAlchemy()


def init_db(app) -> None:
    """Bind the database to a Flask app and create tables."""
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()