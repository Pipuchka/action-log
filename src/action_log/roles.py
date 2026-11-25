"""Роли и права на работу с журналом."""

from enum import Enum


class Role(str, Enum):
    USER = "user"
    AUDITOR = "auditor"
    ADMIN = "admin"


class Permission(str, Enum):
    LOG_READ_OWN = "log:read_own"
    LOG_READ_ALL = "log:read_all"
    LOG_EXPORT = "log:export"
    LOG_PURGE = "log:purge"


# Матрица «роль -> набор прав». Меняйте здесь, если нужны другие правила.
ROLE_PERMISSIONS = {
    Role.USER: {Permission.LOG_READ_OWN},
    Role.AUDITOR: {Permission.LOG_READ_OWN, Permission.LOG_READ_ALL, Permission.LOG_EXPORT},
    Role.ADMIN: set(Permission),
}


def has_permission(role, permission):
    """True, если у роли есть право."""
    return Permission(permission) in ROLE_PERMISSIONS[Role(role)]
