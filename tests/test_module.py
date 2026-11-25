import csv
import io

import pytest

from action_log import (
    AccessDenied,
    ActionLog,
    Level,
    ValidationError,
    has_permission,
    parse_level,
)

USER = {"id": 1, "username": "ivan", "role": "user"}
OTHER = {"id": 2, "username": "maria", "role": "user"}
AUDITOR = {"id": 3, "username": "audit", "role": "auditor"}
ADMIN = {"id": 4, "username": "root", "role": "admin"}
ANON = {"id": None, "username": "anonymous", "role": "user"}


@pytest.fixture
def journal():
    ticks = iter(range(1000, 1000000, 10))
    j = ActionLog(":memory:", clock=lambda: next(ticks))
    yield j
    j.close()


# ---- запись ----
def test_log_returns_id_and_record_can_be_read(journal):
    entry_id = journal.log(USER, "auth.login", details={"ip_checked": True}, target="session:1")
    rows = journal.query(USER)
    assert [r["id"] for r in rows] == [entry_id]
    assert rows[0]["action"] == "auth.login"
    assert rows[0]["level_name"] == "INFO"
    assert rows[0]["username"] == "ivan"
    assert rows[0]["target"] == "session:1"


def test_records_below_min_level_are_dropped():
    j = ActionLog(":memory:", min_level="warning")
    assert j.info(USER, "note.create") is None
    assert j.debug(USER, "note.view") is None
    assert j.warning(USER, "auth.failed") is not None
    assert j.count(ADMIN) == 1


@pytest.mark.parametrize("name", ["debug", "INFO", " Warning ", 40, Level.CRITICAL])
def test_parse_level_accepts_names_numbers_and_enum(name):
    assert isinstance(parse_level(name), Level)


@pytest.mark.parametrize("bad", ["fatal", 25, True, None, 3.5])
def test_parse_level_rejects_unknown(bad):
    with pytest.raises(ValidationError):
        parse_level(bad)


@pytest.mark.parametrize("action", ["", "with space", "x" * 65, None, "рус"])
def test_invalid_action_rejected(journal, action):
    with pytest.raises(ValidationError):
        journal.log(USER, action)


def test_invalid_actor_rejected(journal):
    for bad in (
        {},
        {"username": "x"},
        {"username": " ", "role": "user"},
        {"username": "x", "role": "king"},
        {"username": "x", "role": "user", "id": "7"},
    ):
        with pytest.raises(ValidationError):
            journal.log(bad, "auth.login")


def test_anonymous_actor_can_be_logged(journal):
    journal.warning(ANON, "auth.login_failed", details={"username": "ghost"})
    row = journal.query(ADMIN)[0]
    assert row["user_id"] is None and row["username"] == "anonymous"


def test_sensitive_details_are_masked(journal):
    journal.log(
        USER, "auth.login", details={"username": "ivan", "password": "qwerty", "API_Token": "abc"}
    )
    details = journal.query(USER)[0]["details"]
    assert "qwerty" not in details and "abc" not in details
    assert details.count("***") == 2 and "ivan" in details


def test_long_details_are_truncated(journal):
    journal.log(USER, "note.create", details="я" * 5000)
    assert len(journal.query(USER)[0]["details"]) == 1001


# ---- чтение и права ----
def test_user_sees_only_own_records(journal):
    journal.info(USER, "note.create")
    journal.info(OTHER, "note.create")
    assert [r["username"] for r in journal.query(USER)] == ["ivan"]
    assert journal.count(USER) == 1
    assert journal.count(ADMIN) == 2


def test_user_cannot_request_foreign_records(journal):
    with pytest.raises(AccessDenied):
        journal.query(USER, user_id=2)
    with pytest.raises(AccessDenied):
        journal.query(ANON)


def test_auditor_and_admin_see_everything_and_can_filter_by_user(journal):
    journal.info(USER, "note.create")
    journal.info(OTHER, "note.delete")
    assert len(journal.query(AUDITOR)) == 2
    assert [r["username"] for r in journal.query(AUDITOR, user_id=2)] == ["maria"]


def test_filters_by_level_action_text_and_time(journal):
    journal.info(USER, "note.create", details="Купить хлеб")
    journal.warning(USER, "auth.login_failed", target="user:ghost")
    journal.error(OTHER, "app.error")
    assert len(journal.query(ADMIN, min_level="warning")) == 2
    assert [r["action"] for r in journal.query(ADMIN, level="error")] == ["app.error"]
    assert [r["action"] for r in journal.query(ADMIN, action="auth.")] == ["auth.login_failed"]
    assert [r["action"] for r in journal.query(ADMIN, text="хлеб")] == ["note.create"]
    assert len(journal.query(ADMIN, since=1010)) == 2
    assert len(journal.query(ADMIN, until=1010)) == 2


def test_like_wildcards_in_filters_are_literal(journal):
    journal.info(USER, "note.create", details="100% done")
    journal.info(USER, "note.delete", details="plain")
    assert len(journal.query(ADMIN, text="%")) == 1
    assert len(journal.query(ADMIN, action="note_")) == 0


def test_pagination_and_newest_first(journal):
    for i in range(5):
        journal.info(USER, f"act.{i}")
    page1 = journal.query(USER, limit=2)
    page2 = journal.query(USER, limit=2, offset=2)
    assert [r["action"] for r in page1] == ["act.4", "act.3"]
    assert [r["action"] for r in page2] == ["act.2", "act.1"]


# ---- сводка, экспорт, очистка ----
def test_stats_for_auditor_only(journal):
    journal.info(USER, "note.create")
    journal.info(OTHER, "note.create")
    journal.error(USER, "app.error")
    stats = journal.stats(AUDITOR)
    assert stats["total"] == 3
    assert stats["by_level"]["INFO"] == 2 and stats["by_level"]["ERROR"] == 1
    assert stats["top_actions"][0] == ("note.create", 2)
    assert stats["top_users"][0] == ("ivan", 2)
    with pytest.raises(AccessDenied):
        journal.stats(USER)


def test_export_csv_contains_rows_and_is_protected(journal):
    journal.warning(USER, "auth.login_failed", details="a,b")
    rows = list(csv.reader(io.StringIO(journal.export_csv(AUDITOR))))
    assert rows[0][:3] == ["id", "time", "level"]
    assert rows[1][2] == "WARNING" and rows[1][6] == "a,b"
    with pytest.raises(AccessDenied):
        journal.export_csv(USER)


def test_csv_injection_is_neutralised(journal):
    journal.info(USER, "note.create", details='=HYPERLINK("http://evil")')
    text = journal.export_csv(ADMIN)
    assert "'=HYPERLINK" in text


def test_purge_removes_old_records_and_logs_itself(journal):
    for _ in range(3):
        journal.info(USER, "note.create")  # время 1000, 1010, 1020
    deleted = journal.purge(ADMIN, older_than=1015)
    assert deleted == 2
    actions = [r["action"] for r in journal.query(ADMIN)]
    assert actions[0] == "log.purge" and actions.count("note.create") == 1


def test_only_admin_can_purge(journal):
    with pytest.raises(AccessDenied):
        journal.purge(AUDITOR, older_than=10**9)
    with pytest.raises(AccessDenied):
        journal.purge(USER, older_than=10**9)


def test_permission_matrix():
    assert has_permission("user", "log:read_own")
    assert not has_permission("user", "log:read_all")
    assert has_permission("auditor", "log:export")
    assert not has_permission("auditor", "log:purge")
    assert has_permission("admin", "log:purge")
