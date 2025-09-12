import uuid

from data.models import db


class BaseModel:
    """Modelo base para todas las tablas."""

    created_at: int
    updated_at: int
    created_by: int
    updated_by: int
    is_active: bool
    uuid: uuid.UUID

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Fusiona anotaciones heredadas en la subclase para que Fastlite las vea
        merged = {}
        for base in cls.__mro__[1:]:
            merged.update(getattr(base, "__annotations__", {}) or {})
        own = getattr(cls, "__annotations__", {}) or {}
        cls.__annotations__ = {**merged, **own}


class AuthUser(BaseModel):
    """Usuario del sistema - identidad básica para login."""
    id: int
    username: str
    email: str
    password_hash: str
    last_login: int | None  # Unix timestamp


class AuthGroup(BaseModel):
    """Grupos de usuarios para autorización (roles amplios)."""
    id: int
    name: str
    description: str | None


class AuthMembership(BaseModel):
    """Tabla de paso: asignación de usuarios a grupos."""
    id: int
    auth_user_id: int
    auth_group_id: int


class AuthPermissions(BaseModel):
    """This table is to set explicit permissions for users to arbitrary resources, like pages or API endpoints."""
    id: int
    name: str
    auth_user_id: int
    resource: str
    allowed: bool


def create_auth_tables():
    auth_users = db.create(
        AuthUser,
        transform=True,
        not_null={"email", "password_hash"},
        defaults={"is_active": True},
    )

    auth_users.create_index(["email"], unique=True, if_not_exists=True)

    auth_groups = db.create(
        AuthGroup,
        transform=True,
        not_null={"name", "is_active"},
        defaults={"is_active": True},
    )

    auth_memberships = db.create(
        AuthMembership,
        foreign_keys=[("auth_user_id", "auth_user"), ("auth_group_id", "auth_group")],
        transform=True,
        not_null={"auth_user_id", "auth_group_id"},
    )

    auth_permissions = db.create(
        AuthPermissions,
        not_null={"name", "auth_user_id", "resource"},
        foreign_keys=["auth_user_id"],
        defaults={"allowed": False},
        transform=True,
    )

    return auth_users, auth_groups, auth_memberships, auth_permissions


create_auth_tables()
