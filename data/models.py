

from data.models import db

# ====================================================================
# MÓDULO DE AUTENTICACIÓN/AUTORIZACIÓN REUTILIZABLE
# ====================================================================


class BaseModel:
    """Modelo base para todas las tablas."""
    created_at: int
    updated_at: int

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
    first_name:str | None
    last_name:str | None
    is_active: bool
    last_login:int | None  # Unix timestamp


auth_users = db.create(
    AuthUser,
    pk="email",
    transform=True,
    not_null={"username", "email", "password_hash", "is_active"},
    defaults={"is_active": True},
)


class AuthGroup(BaseModel):
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


class AuthMembership(BaseModel):
    """Tabla de paso: asignación de usuarios a grupos."""

    uuid: str
    auth_user: str
    auth_group: int
    assigned_at:int | None  # Unix timestamp


auth_memberships = db.create(
    AuthMembership,
    pk="uuid",
    foreign_keys=[("auth_user", "auth_user"), ("auth_group", "auth_group")],
    transform=True,
    not_null={"auth_user", "auth_group"},
)


class AuthPermissions(BaseModel):
    uuid: str
    name: str
    group_id: int


auth_permissions = db.create(AuthPermissions, pk="uuid", transform=True)
