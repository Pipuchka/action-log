import pytest

from app import create_app
from seed import seed


@pytest.fixture
def app(tmp_path):
    app = create_app(db_path=str(tmp_path / "journal.db"), secret_key="test")
    seed(app)
    return app


PASSWORDS = {"admin": "admin12345", "auditor": "auditor12345"}


class Browser:
    """Обёртка над test client: сама подставляет CSRF-токен в POST."""

    def __init__(self, client):
        self.c = client

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, data=None, **kw):
        self.c.get("/login")  # создаёт csrf в сессии
        with self.c.session_transaction() as s:
            token = s["csrf"]
        return self.c.post(url, data={**(data or {}), "csrf": token}, **kw)

    def login(self, username, password=None):
        password = password or PASSWORDS.get(username, "user12345678")
        return self.post("/login", {"username": username, "password": password})


def new_web(app, username=None):
    web = Browser(app.test_client())
    if username:
        web.login(username)
    return web


def entries(app, **filters):
    admin = {"id": 1, "username": "admin", "role": "admin"}
    return app.extensions["journal"].query(admin, **filters)


# seed: пользователи 1 admin, 2 auditor, 3 ivan, 4 maria; заметки 1 (ivan), 2 (maria)


def test_login_is_logged_without_password(app):
    new_web(app, "ivan")
    first = entries(app)[0]
    assert first["action"] == "auth.login" and first["username"] == "ivan"
    assert "user12345678" not in str(entries(app))


def test_failed_login_logged_as_warning_for_anonymous(app):
    web = new_web(app)
    r = web.login("ivan", "wrong-password")
    assert "Неверный логин или пароль" in r.get_data(as_text=True)
    row = entries(app)[0]
    assert row["action"] == "auth.login_failed" and row["level_name"] == "WARNING"
    assert row["user_id"] is None and "ivan" in row["details"]


def test_register_and_logout_are_logged(app):
    web = new_web(app)
    web.post("/register", {"username": "petr", "password": "password1"})
    web.login("petr", "password1")
    web.post("/logout")
    actions = [e["action"] for e in entries(app)]
    assert actions[:3] == ["auth.logout", "auth.login", "auth.register"]


def test_notes_pages_require_login(app):
    r = new_web(app).get("/notes")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_note_create_and_delete_are_logged(app):
    web = new_web(app, "ivan")
    web.post("/notes", {"text": "Купить хлеб"})
    assert "Купить хлеб" in web.get("/notes").get_data(as_text=True)
    web.post("/notes/3/delete")
    actions = [(e["action"], e["target"]) for e in entries(app)[:2]]
    assert actions == [("note.delete", "note:3"), ("note.create", "note:3")]


def test_deleting_foreign_note_is_denied_and_logged(app):
    web = new_web(app, "ivan")
    r = web.post("/notes/2/delete")  # заметка maria
    assert r.status_code == 403
    row = entries(app)[0]
    assert row["action"] == "access.denied" and row["level_name"] == "WARNING"


def test_empty_note_rejected(app):
    web = new_web(app, "ivan")
    r = web.post("/notes", {"text": "   "}, follow_redirects=True)
    assert "от 1 до 200" in r.get_data(as_text=True)


def test_user_sees_only_own_entries_in_journal(app):
    new_web(app, "maria")
    ivan = new_web(app, "ivan")
    page = ivan.get("/journal").get_data(as_text=True)
    assert "только ваши записи" in page and ">ivan<" in page and ">maria<" not in page


def test_auditor_sees_all_and_can_filter_by_level(app):
    new_web(app, "ivan").login("ivan", "bad-password")
    auditor = new_web(app, "auditor")
    page = auditor.get("/journal?level=WARNING").get_data(as_text=True)
    assert "auth.login_failed" in page and "auth.login<" not in page


def test_user_cannot_open_stats_export_or_purge(app):
    ivan = new_web(app, "ivan")
    assert ivan.get("/journal/stats").status_code == 403
    assert ivan.get("/journal/export.csv").status_code == 403
    assert ivan.get("/admin/purge").status_code == 403


def test_auditor_stats_and_export(app):
    web = new_web(app, "auditor")
    assert "Всего записей" in web.get("/journal/stats").get_data(as_text=True)
    r = web.get("/journal/export.csv")
    assert r.status_code == 200 and r.mimetype == "text/csv"
    assert "auth.login" in r.get_data(as_text=True)
    assert web.get("/admin/purge").status_code == 403


def test_diagnostics_events_and_level_threshold(app):
    web = new_web(app, "ivan")
    web.post("/diagnostics/error")
    web.post("/diagnostics/critical")
    web.post("/diagnostics/debug")  # ниже порога INFO — не записывается
    actions = [e["action"] for e in entries(app)[:2]]
    assert actions == ["diagnostics.critical", "diagnostics.error"]
    assert not any(e["action"] == "diagnostics.debug" for e in entries(app))


def test_admin_purge_clears_old_and_logs_itself(app):
    new_web(app, "ivan")
    admin = new_web(app, "admin")
    admin.post("/admin/purge", {"days": "0"})
    first = entries(app)[0]
    assert first["action"] == "log.purge" and first["level_name"] == "WARNING"


def test_post_without_csrf_rejected(app):
    r = app.test_client().post("/login", data={"username": "ivan", "password": "user12345678"})
    assert r.status_code == 400
