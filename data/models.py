from fasthtml.common import database

db = database("data/database.sqlite")


# ====================================================================
# MÓDULO DE AUTENTICACIÓN/AUTORIZACIÓN REUTILIZABLE
# ====================================================================


class AuthUser:
    """Usuario del sistema - identidad básica para login."""

    id: int
    username: str
    email: str
    password_hash: str
    first_name:str | None
    last_name:str | None
    is_active: bool
    created_at:int | None  # Unix timestamp
    last_login:int | None  # Unix timestamp


auth_users = db.create(
    AuthUser,
    pk="id",
    transform=True,
    not_null={"username", "email", "password_hash", "is_active"},
    defaults={"is_active": True},
)


class AuthGroup:
    """Grupos de usuarios para autorización (roles amplios)."""

    id: int
    name: str
    description:str | None
    is_active: bool


auth_groups = db.create(
    AuthGroup,
    pk="id",
    transform=True,
    not_null={"name", "is_active"},
    defaults={"is_active": True},
)


class AuthMembership:
    """Tabla de paso: asignación de usuarios a grupos."""

    id: int
    user_id: int
    group_id: int
    assigned_at:int | None  # Unix timestamp


auth_memberships = db.create(
    AuthMembership,
    pk="id",
    transform=True,
    not_null={"user_id", "group_id"},
    foreign_keys=["auth_user_id", "auth_group_id"],
)


class AuthPermissions:
    uuid: str
    name: str
    group_id: int


auth_permissions = db.create(AuthPermissions, pk="uuid", transform=True)
