"""Создаёт демонстрационных пользователей и заметки: python src/seed.py"""

import time

from werkzeug.security import generate_password_hash

from app import create_app

DEMO_USERS = [
    ("admin", "admin12345", "admin"),
    ("auditor", "auditor12345", "auditor"),
    ("ivan", "user12345678", "user"),
    ("maria", "user12345678", "user"),
]

DEMO_NOTES = [
    ("ivan", "Сдать отчёт по практике"),
    ("maria", "Подготовиться к защите проекта"),
]


def seed(app):
    db = app.extensions["db"]
    created = []
    for username, password, role in DEMO_USERS:
        if not db.one("SELECT 1 AS x FROM users WHERE username = ?", (username,)):
            db.run(
                "INSERT INTO users(username, password_hash, role) VALUES (?,?,?)",
                (username, generate_password_hash(password), role),
            )
            created.append(username)
    if not db.one("SELECT 1 AS x FROM notes"):
        for author, text in DEMO_NOTES:
            user = db.one("SELECT id FROM users WHERE username = ?", (author,))
            db.run(
                "INSERT INTO notes(user_id, text, created_at) VALUES (?,?,?)",
                (user["id"], text, int(time.time())),
            )
        created.append("заметки")
    return created


if __name__ == "__main__":
    done = seed(create_app())
    print("Создано:", ", ".join(done) if done else "ничего (данные уже есть)")
