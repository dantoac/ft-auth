from fasthtml.common import database

db = database("data/database.sqlite")


class AuthUsers:
    id: int
    uuid: str
    username: str
    email: str
    rut: str
    password_hash: str
    created_at: int
    updated_at: int
    role: int


class AuthGroups:
    id: int
    name: str


class AuthPermissions:
    id: int
    name: str
    group_id: int


auth_groups = db.create(AuthGroups, pk="id", transform=True, not_null={"name"})
auth_groups.upsert(id=1, name="Admin")
auth_groups.upsert(id=2, name="User")
auth_users = db.create(
    AuthUsers, pk="email", transform=True, not_null={"uuid"}, defaults=dict(role=2)
)
auth_permissions = db.create(AuthPermissions, pk="id", transform=True)
