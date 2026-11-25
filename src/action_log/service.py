"""Журнал действий пользователей с уровнями важности."""

import csv
import io
import json
import re
import sqlite3
import threading
import time

from .errors import AccessDenied, ValidationError
from .levels import Level, parse_level
from .roles import Permission, Role, has_permission

_SCHEMA = """
CREATE TABLE IF NOT EXISTS log_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    level      INTEGER NOT NULL,
    user_id    INTEGER,
    username   TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    details    TEXT,
    ip         TEXT
);
CREATE INDEX IF NOT EXISTS idx_log_created ON log_entries(created_at);
CREATE INDEX IF NOT EXISTS idx_log_user ON log_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_log_level ON log_entries(level);
"""

_ACTION_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
# Ключи в details, значения которых скрываются, чтобы пароли и токены не попали в журнал.
_SENSITIVE = ("password", "passwd", "token", "secret", "key", "card")


def _like(text):
    """Экранирует символы шаблона LIKE, чтобы поиск шёл по буквальному тексту."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class ActionLog:
    """Запись и чтение журнала действий.

    :param db_path: путь к SQLite-файлу или ":memory:".
    :param min_level: записи ниже этого уровня не сохраняются.
    :param clock: функция текущего времени в секундах (для тестов можно подменить).
    """

    def __init__(self, db_path=":memory:", min_level=Level.INFO, clock=time.time):
        self.min_level = parse_level(min_level)
        self._clock = clock
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # ---------- запись ----------
    def log(self, actor, action, level=Level.INFO, details=None, target=None, ip=None):
        """Добавляет запись и возвращает её id. Если уровень ниже min_level, возвращает None."""
        username = self._check_actor(actor)
        if not isinstance(action, str) or not _ACTION_RE.match(action):
            raise ValidationError("Действие: 1-64 символа (латиница, цифры, _ . : -)")
        level = parse_level(level)
        if level < self.min_level:
            return None
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO log_entries(created_at, level, user_id, username, action, target, "
                "details, ip) VALUES (?,?,?,?,?,?,?,?)",
                (
                    int(self._clock()),
                    int(level),
                    actor.get("id"),
                    username,
                    action,
                    target,
                    self._format_details(details),
                    ip,
                ),
            )
            self._db.commit()
            return cur.lastrowid

    def debug(self, actor, action, **kw):
        return self.log(actor, action, Level.DEBUG, **kw)

    def info(self, actor, action, **kw):
        return self.log(actor, action, Level.INFO, **kw)

    def warning(self, actor, action, **kw):
        return self.log(actor, action, Level.WARNING, **kw)

    def error(self, actor, action, **kw):
        return self.log(actor, action, Level.ERROR, **kw)

    def critical(self, actor, action, **kw):
        return self.log(actor, action, Level.CRITICAL, **kw)

    # ---------- чтение ----------
    def query(
        self,
        actor,
        min_level=None,
        level=None,
        user_id=None,
        action=None,
        text=None,
        since=None,
        until=None,
        limit=100,
        offset=0,
    ):
        """Список записей, новые первыми. Обычный пользователь видит только свои записи."""
        where, args = self._filters(actor, min_level, level, user_id, action, text, since, until)
        sql = "SELECT * FROM log_entries" + where + " ORDER BY id DESC LIMIT ? OFFSET ?"
        rows = self._db.execute(sql, (*args, int(limit), int(offset))).fetchall()
        return [self._public(r) for r in rows]

    def count(
        self,
        actor,
        min_level=None,
        level=None,
        user_id=None,
        action=None,
        text=None,
        since=None,
        until=None,
    ):
        where, args = self._filters(actor, min_level, level, user_id, action, text, since, until)
        row = self._db.execute("SELECT COUNT(*) AS n FROM log_entries" + where, args).fetchone()
        return row["n"]

    def stats(self, actor, since=None):
        """Сводка: записей по уровням, самые частые действия и пользователи."""
        self._require(actor, Permission.LOG_READ_ALL)
        where, args = ("", ())
        if since is not None:
            where, args = " WHERE created_at >= ?", (int(since),)
        by_level = {lvl.name: 0 for lvl in Level}
        for r in self._db.execute(
            "SELECT level, COUNT(*) AS n FROM log_entries" + where + " GROUP BY level", args
        ):
            by_level[Level(r["level"]).name] = r["n"]
        top_actions = self._db.execute(
            "SELECT action, COUNT(*) AS n FROM log_entries"
            + where
            + " GROUP BY action ORDER BY n DESC, action LIMIT 10",
            args,
        ).fetchall()
        top_users = self._db.execute(
            "SELECT username, COUNT(*) AS n FROM log_entries"
            + where
            + " GROUP BY username ORDER BY n DESC, username LIMIT 10",
            args,
        ).fetchall()
        return {
            "total": sum(by_level.values()),
            "by_level": by_level,
            "top_actions": [(r["action"], r["n"]) for r in top_actions],
            "top_users": [(r["username"], r["n"]) for r in top_users],
        }

    def export_csv(self, actor, **filters):
        """Все записи, подходящие под фильтры, в виде CSV-текста."""
        self._require(actor, Permission.LOG_EXPORT)
        filters.setdefault("limit", 100000)
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["id", "time", "level", "user", "action", "target", "details", "ip"])
        for e in self.query(actor, **filters):
            row = [
                e["id"],
                e["created_at"],
                e["level_name"],
                e["username"],
                e["action"],
                e["target"] or "",
                e["details"] or "",
                e["ip"] or "",
            ]
            writer.writerow([self._csv_safe(v) for v in row])
        return out.getvalue()

    # ---------- обслуживание ----------
    def purge(self, actor, older_than):
        """Удаляет записи старше older_than (секунды). Только администратор. Возвращает число."""
        self._require(actor, Permission.LOG_PURGE)
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM log_entries WHERE created_at < ?", (int(older_than),)
            )
            deleted = cur.rowcount
            self._db.commit()
        # сама очистка тоже попадает в журнал
        self.log(actor, "log.purge", Level.WARNING, details={"deleted": deleted})
        return deleted

    def close(self):
        self._db.close()

    # ---------- служебное ----------
    def _filters(self, actor, min_level, level, user_id, action, text, since, until):
        self._check_actor(actor)
        conds, args = [], []
        if not has_permission(actor["role"], Permission.LOG_READ_ALL):
            if user_id is not None and user_id != actor.get("id"):
                raise AccessDenied("Можно смотреть только свои записи")
            if actor.get("id") is None:
                raise AccessDenied("Журнал доступен только вошедшим пользователям")
            user_id = actor["id"]
        if min_level is not None:
            conds.append("level >= ?")
            args.append(int(parse_level(min_level)))
        if level is not None:
            conds.append("level = ?")
            args.append(int(parse_level(level)))
        if user_id is not None:
            conds.append("user_id = ?")
            args.append(user_id)
        if action:
            conds.append("action LIKE ? ESCAPE '\\'")
            args.append(_like(action) + "%")
        if text:
            conds.append(
                "(details LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' "
                "OR target LIKE ? ESCAPE '\\')"
            )
            like = "%" + _like(text) + "%"
            args += [like, like, like]
        if since is not None:
            conds.append("created_at >= ?")
            args.append(int(since))
        if until is not None:
            conds.append("created_at <= ?")
            args.append(int(until))
        return (" WHERE " + " AND ".join(conds) if conds else ""), tuple(args)

    @staticmethod
    def _format_details(details):
        if details is None:
            return None
        if isinstance(details, dict):
            masked = {
                k: ("***" if any(s in str(k).lower() for s in _SENSITIVE) else v)
                for k, v in details.items()
            }
            text = json.dumps(masked, ensure_ascii=False, default=str)
        else:
            text = str(details)
        return text if len(text) <= 1000 else text[:1000] + "…"

    @staticmethod
    def _csv_safe(value):
        """Защита от CSV-инъекций: значение, начинающееся с = + - @, получает префикс."""
        text = str(value)
        return "'" + text if text[:1] in ("=", "+", "-", "@") else text

    @staticmethod
    def _public(row):
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "level": row["level"],
            "level_name": Level(row["level"]).name,
            "user_id": row["user_id"],
            "username": row["username"],
            "action": row["action"],
            "target": row["target"],
            "details": row["details"],
            "ip": row["ip"],
        }

    @staticmethod
    def _check_actor(actor):
        try:
            Role(actor["role"])
            username = actor["username"]
            ok = isinstance(username, str) and bool(username.strip())
            ok = ok and (actor.get("id") is None or isinstance(actor.get("id"), int))
        except (KeyError, TypeError, ValueError, AttributeError):
            ok = False
        if not ok:
            raise ValidationError("Некорректный пользователь (нужны username, role, id или None)")
        return actor["username"].strip()

    @staticmethod
    def _require(actor, permission):
        ActionLog._check_actor(actor)
        if not has_permission(actor["role"], permission):
            raise AccessDenied(f"Нет права {Permission(permission).value}")
