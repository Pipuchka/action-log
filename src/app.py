"""Журнал действий: Flask + Jinja2, логирование построено на модуле action_log."""

import os
import re
import secrets
import sqlite3
import time
from functools import wraps

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from action_log import AccessDenied, ActionLog, Level, ValidationError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PER_PAGE = 15
DAY = 86400

_HOST_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    text       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
ANONYMOUS = {"id": None, "username": "anonymous", "role": "user"}


class Database:
    """Таблицы самого сайта (пользователи и заметки). Журнал хранит модуль."""

    def __init__(self, path):
        self.path = path
        with self.connect() as db:
            db.executescript(_HOST_SCHEMA)

    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def one(self, sql, args=()):
        db = self.connect()
        try:
            row = db.execute(sql, args).fetchone()
        finally:
            db.close()
        return dict(row) if row else None

    def all(self, sql, args=()):
        db = self.connect()
        try:
            rows = db.execute(sql, args).fetchall()
        finally:
            db.close()
        return [dict(r) for r in rows]

    def run(self, sql, args=()):
        db = self.connect()
        try:
            cur = db.execute(sql, args)
            db.commit()
            return cur.lastrowid
        finally:
            db.close()


def create_app(db_path=None, secret_key=None, min_level=None):
    app = Flask(__name__)
    app.secret_key = secret_key or os.environ.get("JOURNAL_SECRET", "dev-secret-change-me")
    path = db_path or os.environ.get("JOURNAL_DB", os.path.join(BASE_DIR, "journal.db"))
    db = Database(path)
    # Один журнал на всё приложение. Порог уровня можно задать переменной LOG_LEVEL.
    journal = ActionLog(db_path=path, min_level=min_level or os.environ.get("LOG_LEVEL", "INFO"))
    app.extensions["db"] = db
    app.extensions["journal"] = journal

    def actor():
        return g.user or ANONYMOUS

    def record(level, action, **kw):
        """Короткая запись события от имени текущего пользователя."""
        return journal.log(actor(), action, level, ip=request.remote_addr, **kw)

    # ---------- общее ----------
    @app.before_request
    def load_user():
        g.user = None
        if session.get("user_id"):
            g.user = db.one(
                "SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],)
            )

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = session.get("csrf")
            if not token or request.form.get("csrf") != token:
                abort(400, "Неверный CSRF-токен")

    @app.context_processor
    def inject_globals():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf"], "user": g.user, "Level": Level}

    @app.template_filter("dictexcept")
    def dictexcept(data, key):
        """Копия словаря без одного ключа (для ссылок постраничного вывода)."""
        return {k: v for k, v in data.items() if k != key}

    @app.template_filter("dt")
    def dt_filter(ts):
        return time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(ts))

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapper

    # ---------- ошибки ----------
    @app.errorhandler(AccessDenied)
    def on_denied(err):
        record(Level.WARNING, "access.denied", target=request.path, details=str(err))
        return render_template("error.html", code=403, message=str(err)), 403

    @app.errorhandler(400)
    def on_bad_request(err):
        return render_template("error.html", code=400, message=err.description), 400

    @app.errorhandler(500)
    def on_server_error(err):
        record(Level.ERROR, "app.exception", target=request.path, details=type(err).__name__)
        return render_template("error.html", code=500, message="Внутренняя ошибка сервера"), 500

    # ---------- вход и регистрация ----------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not _USERNAME_RE.match(username):
                flash("Логин: 3-32 символа (латиница, цифры, _ . -)", "error")
            elif len(password) < 8:
                flash("Пароль должен быть не короче 8 символов", "error")
            elif db.one("SELECT 1 AS x FROM users WHERE username = ?", (username,)):
                flash("Логин уже занят", "error")
            else:
                user_id = db.run(
                    "INSERT INTO users(username, password_hash, role) VALUES (?,?,?)",
                    (username, generate_password_hash(password), "user"),
                )
                journal.info(
                    {"id": user_id, "username": username, "role": "user"},
                    "auth.register",
                    ip=request.remote_addr,
                )
                flash("Регистрация успешна. Теперь войдите.", "ok")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            row = db.one(
                "SELECT id, username, role, password_hash FROM users WHERE username = ?",
                (username,),
            )
            if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
                session["user_id"] = row["id"]
                journal.info(
                    {"id": row["id"], "username": row["username"], "role": row["role"]},
                    "auth.login",
                    ip=request.remote_addr,
                )
                return redirect(url_for("notes"))
            # Пароль в журнал не попадает, только введённый логин.
            record(Level.WARNING, "auth.login_failed", details={"username": username[:32]})
            flash("Неверный логин или пароль", "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        if g.user:
            record(Level.INFO, "auth.logout")
        session.pop("user_id", None)
        return redirect(url_for("login"))

    @app.get("/")
    def index():
        return redirect(url_for("notes" if g.user else "login"))

    # ---------- заметки (то, что порождает события) ----------
    @app.route("/notes", methods=["GET", "POST"])
    @login_required
    def notes():
        if request.method == "POST":
            text = request.form.get("text", "").strip()
            if not text or len(text) > 200:
                flash("Заметка: от 1 до 200 символов", "error")
            else:
                note_id = db.run(
                    "INSERT INTO notes(user_id, text, created_at) VALUES (?,?,?)",
                    (g.user["id"], text, int(time.time())),
                )
                record(
                    Level.INFO, "note.create", target=f"note:{note_id}", details={"text": text[:50]}
                )
                flash("Заметка добавлена", "ok")
            return redirect(url_for("notes"))
        rows = db.all("SELECT * FROM notes WHERE user_id = ? ORDER BY id DESC", (g.user["id"],))
        return render_template("notes.html", notes=rows)

    @app.post("/notes/<int:note_id>/delete")
    @login_required
    def note_delete(note_id):
        note = db.one("SELECT * FROM notes WHERE id = ?", (note_id,))
        if note is None:
            abort(404)
        if note["user_id"] != g.user["id"]:
            raise AccessDenied("Это чужая заметка")
        db.run("DELETE FROM notes WHERE id = ?", (note_id,))
        record(Level.INFO, "note.delete", target=f"note:{note_id}")
        flash("Заметка удалена", "ok")
        return redirect(url_for("notes"))

    # ---------- диагностика: события разных уровней ----------
    @app.get("/diagnostics")
    @login_required
    def diagnostics():
        return render_template("diagnostics.html", min_level=journal.min_level)

    @app.post("/diagnostics/<kind>")
    @login_required
    def diagnostics_run(kind):
        if kind not in ("debug", "warning", "error", "critical"):
            abort(404)
        entry_id = record(Level[kind.upper()], f"diagnostics.{kind}", details="Тестовое событие")
        flash(
            "Событие записано в журнал" if entry_id else "Событие ниже порога уровня, не записано",
            "ok",
        )
        return redirect(url_for("diagnostics"))

    # ---------- журнал ----------
    def parse_filters():
        """Фильтры из адресной строки -> аргументы для journal.query / count."""
        args = request.args
        filters = {}
        if args.get("level"):
            filters["min_level"] = args["level"]
        if args.get("action"):
            filters["action"] = args["action"].strip()
        if args.get("q"):
            filters["text"] = args["q"].strip()
        if args.get("user") and args["user"].isdigit():
            filters["user_id"] = int(args["user"])
        if args.get("days") and args["days"].isdigit():
            filters["since"] = int(time.time()) - int(args["days"]) * DAY
        return filters

    @app.get("/journal")
    @login_required
    def journal_page():
        filters = parse_filters()
        try:
            total = journal.count(g.user, **filters)
            raw_page = request.args.get("page", "1")
            page = int(raw_page) if raw_page.isdigit() and int(raw_page) > 0 else 1
            entries = journal.query(g.user, limit=PER_PAGE, offset=(page - 1) * PER_PAGE, **filters)
        except ValidationError as err:
            flash(str(err), "error")
            total, page, entries = 0, 1, []
        users = db.all("SELECT id, username FROM users ORDER BY username")
        return render_template(
            "journal.html",
            entries=entries,
            total=total,
            page=page,
            pages=max((total + PER_PAGE - 1) // PER_PAGE, 1),
            users=users,
            args=request.args,
        )

    @app.get("/journal/stats")
    @login_required
    def journal_stats():
        days = request.args.get("days", "")
        since = int(time.time()) - int(days) * DAY if days.isdigit() else None
        return render_template("stats.html", stats=journal.stats(g.user, since=since), days=days)

    @app.get("/journal/export.csv")
    @login_required
    def journal_export():
        text = journal.export_csv(g.user, **parse_filters())
        record(Level.INFO, "journal.export")
        return Response(
            "﻿" + text,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=journal.csv"},
        )

    @app.route("/admin/purge", methods=["GET", "POST"])
    @login_required
    def purge():
        if g.user["role"] != "admin":
            raise AccessDenied("Очистка журнала доступна только администратору")
        if request.method == "POST":
            days = request.form.get("days", "")
            if not days.isdigit():
                flash("Укажите число дней (0 и больше)", "error")
            else:
                deleted = journal.purge(g.user, older_than=int(time.time()) - int(days) * DAY)
                flash(f"Удалено записей: {deleted}", "ok")
                return redirect(url_for("purge"))
        return render_template("purge.html")

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
