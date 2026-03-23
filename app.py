import logging
import time
import uuid

import bcrypt
from fasthtml.common import *

from auth.data.models import db, create_auth_tables
from .components import ergonoti

logger = logging.getLogger(__name__)

APP_NAME = "User Auth"
MIN_PASSWORD_LENGTH = 8

auth_users = db.t["auth_user"]
auth_groups = db.t["auth_group"]

rt = APIRouter(prefix="/auth")


ROUTE_AFTER_LOGIN = "/admin/"
ROUTE_AFTER_REGISTER = "/auth/login"
ROUTE_AFTER_LOGOUT = "/auth/login"
ROUTE_AFTER_UPDATE = "/profile"

# --- Rate limiting persistente en SQLite (VULN-09) ---
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60

# Crear tabla de intentos de login si no existe
db.q(
    """
    CREATE TABLE IF NOT EXISTS login_attempt (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        attempted_at REAL NOT NULL
    )
"""
)
db.q(
    "CREATE INDEX IF NOT EXISTS idx_login_attempt_ip ON login_attempt (ip, attempted_at)"
)


def _is_rate_limited(ip: str) -> bool:
    """Verifica si una IP ha excedido el límite de intentos de login."""
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    rows = db.q(
        "SELECT COUNT(*) as cnt FROM login_attempt WHERE ip = ? AND attempted_at >= ?",
        (ip, cutoff),
    )
    return (rows[0]["cnt"] if rows else 0) >= MAX_LOGIN_ATTEMPTS


def _record_login_attempt(ip: str) -> None:
    """Registra un intento de login para la IP dada."""
    db.q(
        "INSERT INTO login_attempt (ip, attempted_at) VALUES (?, ?)",
        (ip, time.time()),
    )
    # Limpieza oportunista de intentos expirados
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    db.q("DELETE FROM login_attempt WHERE attempted_at < ?", (cutoff,))


def _clear_login_attempts(ip: str) -> None:
    """Limpia los intentos de login para una IP tras autenticación exitosa."""
    db.q("DELETE FROM login_attempt WHERE ip = ?", (ip,))


def _requires_login(request, session):
    auth = request.scope["auth"] = session.get("auth", None)
    if not auth:
        return Redirect("/auth/login")


auth_beforeware = Beforeware(
    _requires_login,
    skip=[
        r"/favicon\.ico",
        r".*\.css",
        r".*\.woff2",
        r".*\.js",
        r"/404",
        r"/auth/.*",
    ],
)

app = FastHTML(
    title=APP_NAME,
    before=auth_beforeware,
    theme="dark",
    favicon="favicon.ico",
    hdrs=(
        Link(rel="stylesheet", href="https://cdn.jsdelivr.net/npm/daisyui@5"),
        Script(src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"),
    ),
)


def _verify_password(plain_password: str = None, hashed_password: str = None) -> bool:
    if not all([plain_password, hashed_password]):
        return False
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def _get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


@rt
def logout(session):
    try:
        del session["auth"]
        return Redirect(ROUTE_AFTER_LOGOUT)
    except KeyError:
        return Redirect(ROUTE_AFTER_LOGOUT)


def user_update_form(session):
    """Formulario de actualización de perfil.

    UX-31: La contraseña actual está dentro de la sección colapsable junto
    con los campos de nueva contraseña, dejando claro que solo se necesita
    para cambiar la contraseña.
    """
    return Form(
        H2(
            f"Actualizando datos de {session['auth']['email']}",
            _class="text-xl font-bold mb-4",
        ),
        Div(
            Input(_type="checkbox"),
            Div("Cambiar Contraseña", _class="collapse-title"),
            Div(
                Div(
                    Label(
                        "Contraseña actual",
                        _for="current_password",
                        _class="text-sm font-medium",
                    ),
                    Input(
                        id="current_password",
                        name="current_password",
                        type="password",
                        placeholder="Confirme su contraseña actual",
                        _class="input input-bordered w-full",
                    ),
                ),
                Div(
                    Label(
                        "Nueva contraseña",
                        _for="new_password",
                        _class="text-sm font-medium",
                    ),
                    Input(
                        id="new_password",
                        name="new_password",
                        type="password",
                        placeholder="Nueva contraseña (mínimo 8 caracteres)",
                        minlength="8",
                        _class="input input-bordered w-full",
                    ),
                ),
                Div(
                    Label(
                        "Confirmar nueva contraseña",
                        _for="confirm_password",
                        _class="text-sm font-medium",
                    ),
                    Input(
                        id="confirm_password",
                        name="confirm_password",
                        type="password",
                        placeholder="Confirmar nueva contraseña",
                        minlength="8",
                        _class="input input-bordered w-full bg-base-100",
                    ),
                ),
                _id="change-password",
                _class="collapse-content bg-base-200 gap-4 space-y-4 rounded-lg",
            ),
            _class="collapse collapse-arrow border border-base-300 rounded-md",
            tabindex="0",
        ),
        Div(
            Button(
                I(_class="fas fa-clock-rotate-left"),
                "Cancelar",
                type="reset",
                _class="btn transition-colors duration-300 btn-neutral",
            ),
            Button(
                I(_class="fas fa-user-pen"),
                "Aplicar cambios",
                type="submit",
                _class="btn btn-primary transition-colors duration-300",
            ),
            _class="flex justify-between items-center gap-4 text-sm font-medium text-base-content/70 text-center",
        ),
        _hx_post=user_update,
        _hx_swap="outerHTML",
        _class="rounded-lg gap-2 p-8 bg-base-100 shadow-xl flex flex-col",
    )


def login_form():
    """Formulario de inicio de sesión.

    UX-06: type="email" para validación nativa del navegador.
    UX-19: _required=True en ambos campos para evitar envíos vacíos.
    UX-01: autocomplete="email"/"current-password" para compatibilidad con gestores de contraseñas.
    UX-02: Labels visibles asociadas a cada campo para cumplir WCAG 2.1.
    """
    return Div(
        Form(
            H1(
                I(_class="fas fa-user-circle mr-2"),
                "Iniciar Sesión",
                _class="text-2xl font-bold mb-4",
            ),
            Div(
                Label(
                    "Correo electrónico",
                    _for="email",
                    _class="text-sm font-medium",
                ),
                Input(
                    id="email",
                    name="email",
                    placeholder="correo@ejemplo.com",
                    autocomplete="email",
                    type="email",
                    _required=True,
                    _class="input input-bordered w-full max-w-xs",
                ),
                _class="flex flex-col gap-1 w-full max-w-xs",
            ),
            Div(
                Label(
                    "Contraseña",
                    _for="password",
                    _class="text-sm font-medium",
                ),
                Input(
                    id="password",
                    name="password",
                    type="password",
                    autocomplete="current-password",
                    placeholder="Contraseña",
                    _required=True,
                    _class="input input-bordered w-full max-w-xs",
                ),
                _class="flex flex-col gap-1 w-full max-w-xs",
            ),
            Input(
                id="important",
                type="hidden",
                value="",
                name="important",
                placeholder="very important value please write something",
            ),
            Div(
                A("Crear cuenta", href=register, _class="link link-primary"),
                _class="w-full text-right mt-2",
            ),
            Button(
                I(_class="fas fa-user-circle", _aria_hidden="true"),
                "Entrar",
                _class="btn btn-primary w-full mt-4",
                _type="submit",
                _hx_post=login_post,
            ),
            _class="flex flex-col items-center gap-4 p-8 bg-base-200 rounded-lg shadow-inner shadow-base-content/20",
            _hx_swap="outerHTML",
            _hx_target="#login-form",
        ),
        _class="flex flex-col justify-center items-center h-full w-full select-none",
        _id="login-form",
    )


@rt.get("/login")
def login(session, resource: str = ""):
    """Muestra el formulario de inicio de sesión.

    UX-07: Solo limpia claves de autenticación, preserva tenant_uuid y
    otras claves de sesión no relacionadas con auth.
    """
    for key in ["auth", "user_id", "user_uuid", "email"]:
        session.pop(key, None)
    return user_template(login_form())


def register_form(username: str = "", email: str = ""):
    """Formulario de registro.

    UX-18: Acepta parámetros opcionales para preservar los valores
    ingresados cuando el formulario falla la validación.
    UX-01: autocomplete estándar para compatibilidad con gestores de contraseñas.
    UX-02: Labels visibles asociadas a cada campo para cumplir WCAG 2.1.
    """
    return Div(
        Form(
            H1(
                I(_class="fas fa-user-plus mr-2"),
                "Registro",
                _class="text-2xl font-bold mb-4",
            ),
            Div(
                Label(
                    "Usuario (opcional)",
                    _for="username",
                    _class="text-sm font-medium",
                ),
                Input(
                    id="username",
                    name="username",
                    placeholder="nombre_usuario",
                    autocomplete="username",
                    type="text",
                    value=username,
                    _class="input input-bordered w-full max-w-xs",
                ),
                _class="flex flex-col gap-1 w-full max-w-xs",
            ),
            Div(
                Label(
                    "Correo electrónico",
                    _for="email",
                    _class="text-sm font-medium",
                ),
                Input(
                    id="email",
                    name="email",
                    required=True,
                    placeholder="correo@ejemplo.com",
                    autocomplete="email",
                    type="email",
                    value=email,
                    _class="input input-bordered w-full max-w-xs",
                ),
                _class="flex flex-col gap-1 w-full max-w-xs",
            ),
            Div(
                Label(
                    "Contraseña",
                    _for="password",
                    _class="text-sm font-medium",
                ),
                Input(
                    id="password",
                    name="password",
                    type="password",
                    autocomplete="new-password",
                    placeholder="Mínimo 8 caracteres",
                    _class="input input-bordered w-full max-w-xs",
                    required=True,
                    minlength="8",
                ),
                _class="flex flex-col gap-1 w-full max-w-xs",
            ),
            Div(
                Label(
                    "Confirmar contraseña",
                    _for="confirm_password",
                    _class="text-sm font-medium",
                ),
                Input(
                    id="confirm_password",
                    name="confirm_password",
                    type="password",
                    autocomplete="new-password",
                    placeholder="Repetir contraseña",
                    _class="input input-bordered w-full max-w-xs",
                    required=True,
                    minlength="8",
                ),
                _class="flex flex-col gap-1 w-full max-w-xs",
            ),
            Input(
                id="important",
                type="hidden",
                value="",
                name="important",  # this is just to catch IA spambots crawling forms
                placeholder="very important value please write something",
            ),
            Div(
                A(
                    "¿Ya tienes cuenta? Inicia sesión",
                    href=login,
                    _class="link link-primary",
                ),
                _class="w-full text-right mt-2",
            ),
            Button(
                I(_class="fas fa-user-plus", _aria_hidden="true"),
                "Crear cuenta",
                _class="btn btn-primary w-full mt-4",
                _type="submit",
                _hx_post=register_user,
            ),
            _class="flex flex-col items-center gap-4 p-8 bg-base-200 rounded-lg shadow-inner shadow-base-content/20",
            _hx_swap="outerHTML",
            _hx_target="#register-form",
        ),
        _class="flex flex-col justify-center items-center h-full w-full select-none",
        _id="register-form",
    )


@rt.get("/register")
def register():
    """Muestra el formulario de registro."""
    return user_template(register_form())


@rt.post("/register")
def register_user(
    username: str = "",
    email: str = "",
    password: str = "",
    confirm_password: str = "",
    important: str = "",
):

    # Evitar bots por honeypot
    if len(important.strip()):
        return

    # Validaciones básicas
    if not (len(email) and len(password) and len(confirm_password)):
        return (
            ergonoti(message="Debe completar los campos obligatorios", type="warning"),
            register_form(username=username, email=email),
        )

    if len(password) < MIN_PASSWORD_LENGTH:
        return (
            ergonoti(
                message=f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres",
                type="error",
            ),
            register_form(username=username, email=email),
        )

    if password != confirm_password:
        return (
            ergonoti(message="Las contraseñas no coinciden", type="error"),
            register_form(username=username, email=email),
        )

    # Normalizar username simple
    username = username.strip()

    try:
        # Verificar si ya existe el usuario
        users_with_these_credentials = auth_users("email=?", (email,)) or auth_users(
            "username=?", (username,)
        )

        if len(users_with_these_credentials):
            return (
                ergonoti(message="El usuario ya existe", type="error"),
                register_form(username=username, email=email),
            )

        # Insertar nuevo usuario
        password_hash = _get_password_hash(password)

        auth_users.insert(
            uuid=uuid.uuid4().hex,
            username=username or None,
            email=email,
            password_hash=password_hash,
            created_at=int(time.time()),
            updated_at=int(time.time()),
        )
    except Exception:
        logger.exception("Error al registrar usuario")
        return (
            ergonoti(
                message="Ocurrió un error al registrar el usuario. Intente nuevamente.",
                type="error",
            ),
            register_form(username=username, email=email),
        )
    return Redirect(ROUTE_AFTER_REGISTER)


@rt.post("/login")
def login_post(request, session, email: str, password: str, important: str = ""):
    # si algún script/bot/ia llena el input "important" retorna vacío
    if len(important.strip()):
        return

    # VULN-09: Rate limiting por IP
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip):
        return (
            ergonoti(
                message="Demasiados intentos de inicio de sesión. Espere un momento.",
                type="error",
            ),
            login_form(),
        )

    if session.get("auth"):
        return Redirect(logout)

    if not (len(email) and len(password)):
        return (
            ergonoti(message="Debe completar el formulario", type="warning"),
            login_form(),
        )

    else:
        existing_user = _get_user_by_email(email)

        if existing_user and _verify_password(password, existing_user.password_hash):
            session["auth"] = {
                "user_id": existing_user.id,
                "email": existing_user.email,
                "uuid": existing_user.uuid,
            }

            existing_user.last_login = int(time.time())
            db["auth_user"].update(existing_user)
            _clear_login_attempts(client_ip)
            return Redirect(ROUTE_AFTER_LOGIN)
        else:
            # Registrar intento fallido para rate limiting
            _record_login_attempt(client_ip)
            return (
                ergonoti(message="Credenciales desconocidas", type="error"),
                login_form(),
            )


def _get_user_by_email(email: str):
    user_exists = None
    try:
        user_exists = auth_users("email=?", (email,), limit=1)
    except Exception:
        logger.exception("Error al buscar el usuario")

    return user_exists[0] if user_exists else None


@rt
def profile(session):
    return user_template(user_update_form(session))


@rt.post
def user_update(
    session,
    current_password: str = "",
    new_password: str = "",
    confirm_password: str = "",
):
    """
    Endpoint para actualizar la información del usuario.

    Permite a los usuarios actualizar su contraseña.
    Requiere la contraseña actual para verificación antes de realizar cambios.
    """
    # Asegurarse de que el usuario esté autenticado
    if "auth" not in session:
        return Redirect(ROUTE_AFTER_LOGOUT)

    user = _get_user_by_email(session["auth"]["email"])
    if not user:
        logger.warning("Usuario no encontrado para email: %s", session["auth"]["email"])
        return Redirect(ROUTE_AFTER_LOGOUT)

    # UX-08: Si no se proporcionó contraseña actual, informar que no hay cambios
    if not current_password:
        return user_update_form(session), ergonoti(
            message="No se realizaron cambios", type="info"
        )

    # Verificar la contraseña actual
    if not _verify_password(current_password, user.password_hash):
        return user_update_form(session), ergonoti(
            message="Contraseña actual incorrecta", type="error"
        )

    # Actualizar la contraseña si se proporcionó una nueva y se confirmó
    if len(new_password):
        if new_password != confirm_password:
            return user_update_form(session), ergonoti(
                message="Las contraseñas no coinciden", type="error"
            )
        elif len(new_password) < MIN_PASSWORD_LENGTH:
            return user_update_form(session), ergonoti(
                message=f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres",
                type="error",
            )
        else:
            new_password_hash = _get_password_hash(new_password)

            # Guardar los cambios
            try:
                users_tbl = db.t["auth_user"]
                users_tbl.update(id=user.id, password_hash=new_password_hash)
            except Exception:
                logger.exception("Error al actualizar contraseña del usuario")
                return user_update_form(session), ergonoti(
                    message="Error al actualizar la contraseña. Intente nuevamente.",
                    type="error",
                )
            else:
                return user_update_form(session), ergonoti(
                    message="Contraseña actualizada correctamente", type="success"
                )

    else:
        return user_update_form(session), ergonoti(
            message="La nueva contraseña no puede estar vacía", type="error"
        )


def user_template(content):
    return Div(
        Div(_id="notifications", _class="toast toast-top z-50"),
        Div(content, _id="auth-form-content"),
        _class="flex flex-col justify-center gap-8 items-center w-full min-h-screen bg-base-200 overflow-hidden",
    )


rt.to_app(app)
serve(port=8000)
