import time
import uuid

import bcrypt
from fasthtml.common import *

from auth.data.models import db, create_auth_tables
from .components import ergonoti

APP_NAME = "User Auth"

auth_users = db.t["auth_user"]
auth_groups = db.t["auth_group"]

rt = APIRouter(prefix="/auth")


def requires_login(request, session):
    auth = request.scope["auth"] = session.get("auth", None)
    if not auth:
        return Redirect("/auth")
    return None


auth_beforeware = Beforeware(
    requires_login,
    skip=[
        r"/favicon\.ico",
        r".*\.css",
        r".*\.woff2",
        r".*\.js",
        r"/auth/index",
        r"/auth/",
        r"/auth/login",
        r"/auth/register",
        r"/auth/register_user",
        r"/auth/@.*"
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


def verify_password(plain_password: str = None, hashed_password: str = None) -> bool:
    if not all([plain_password, hashed_password]):
        return False
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


@rt
def logout(session):
    try:
        del session["auth"]
        return Redirect(ROUTE_AFTER_LOGOUT)
    except KeyError:
        return Redirect(ROUTE_AFTER_LOGOUT)


def user_update_form(session):
    return Form(
        H2(
            f"Actualizando datos de {session['auth']['email']}",
            _class="text-xl font-bold mb-4",
        ),
        Div(
            Div(
                Label(
                    "Contraseña actual",
                    _for="current_password",
                    _class="text-sm font-medium",
                )
            ),
            Div(
                Input(
                    id="current_password",
                    name="current_password",
                    type="password",
                    required=True,
                    placeholder="Confirme su contraseña actual",
                    _class="input input-bordered w-full dark:text-slate-600",
                )
            ),
            _class="mb-4",
        ),
        Div(
            Input(_type="checkbox"),
            Div("Cambiar Contraseña", _class="collapse-title"),
            Div(
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
                        placeholder="Nueva contraseña",
                        _class="input input-bordered w-full dark:text-slate-600",
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
                        _class="input input-bordered w-full bg-white dark:text-slate-600",
                    ),
                ),
                _id="change-password",
                _class="collapse-content bg-slate-300 dark:bg-slate-500 gap-4 space-y-4 rounded-lg",
            ),
            _class="collapse collapse-arrow border border-slate-400 rounded-md",
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
            _class="flex justify-between items-center gap-4 text-sm font-medium text-slate-600 text-center",
        ),
        _hx_post=user_update,
        _hx_swap="outerHTML",
        _class="rounded-lg gap-2 p-8 bg-slate-100 dark:bg-slate-900 dark:text-white shadow-xl  flex flex-col",
    )


def login_form():
    return Div(
        Form(
            H1(
                I(_class="fas fa-user-circle mr-2"),
                "Iniciar Sesión",
                _class="text-2xl font-bold mb-4",
            ),
            Input(
                id="email",
                name="email",
                placeholder="email",
                autocomplete="off",
                type="text",
                _class="input input-bordered w-full max-w-xs",
            ),
            Input(
                id="password",
                name="password",
                type="password",
                autocomplete="off",
                placeholder="Contraseña",
                _class="input input-bordered w-full max-w-xs",
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
                I(_class="fas fa-user-circle", _onclick="return false;"),
                "Entrar",
                _class="btn btn-primary w-full mt-4",
                _hx_trigger="click",
                _hx_post=login,
            ),
            _class="flex flex-col items-center gap-4 p-8 bg-slate-300 rounded-lg shadow-inner shadow-slate-900",
            _hx_swap="outerHTML",
            _hx_target="#login-form",
        ),
        _class="flex flex-col justify-center items-center h-full w-full select-none",
        _id="login-form",
    )


@rt.get
@rt.get("/index")
@rt.get("/@{resource}")
def login(session, resource: str = ""):
    session["tenant"] = resource
    """Muestra el formulario de inicio de sesión."""
    return user_template(login_form())


def register_form():
    return Div(
        Form(
            H1(
                I(_class="fas fa-user-plus mr-2"),
                "Registro",
                _class="text-2xl font-bold mb-4",
            ),
            Input(
                id="username",
                name="username",
                placeholder="Usuario (opcional)",
                autocomplete="off",
                type="text",
                _class="input input-bordered w-full max-w-xs",
                required=True,
            ),
            Input(
                id="email",
                name="email",
                required=True,
                placeholder="Correo electrónico",
                autocomplete="off",
                type="email",
                _class="input input-bordered w-full max-w-xs",
            ),
            Input(
                id="password",
                name="password",
                type="password",
                autocomplete="off",
                placeholder="Contraseña",
                _class="input input-bordered w-full max-w-xs",
                required=True,
            ),
            Input(
                id="confirm_password",
                name="confirm_password",
                type="password",
                autocomplete="off",
                placeholder="Confirmar contraseña",
                _class="input input-bordered w-full max-w-xs",
                required=True,
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
                I(_class="fas fa-user-plus", _onclick="return false;"),
                "Crear cuenta",
                _class="btn btn-primary w-full mt-4",
                _hx_trigger="click",
                _hx_post=register_user,
            ),
            _class="flex flex-col items-center gap-4 p-8 bg-slate-300 rounded-lg shadow-inner shadow-slate-900",
            _hx_swap="outerHTML",
            _hx_target="#register-form",
        ),
        _class="flex flex-col justify-center items-center h-full w-full select-none",
        _id="register-form",
    )


@rt
def register():
    """Muestra el formulario de registro."""
    return user_template(register_form())


@rt.post
def register_user(
    username: str = "",
    email: str = "",
    password: str = "",
    confirm_password: str = "",
    important: str = "",
):

    # Evitar bots por honeypot
    if len(important):
        return

    # Validaciones básicas
    if not (len(email) and len(password) and len(confirm_password)):
        return (
            ergonoti(message="Debe completar los campos obligatorios", type="warning"),
            register_form(),
        )

    if password != confirm_password:
        return (
            ergonoti(message="Las contraseñas no coinciden", type="error"),
            register_form(),
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
                register_form(),
            )

        # Insertar nuevo usuario
        password_hash = get_password_hash(password)

        auth_users.insert(
            uuid=uuid.uuid4().hex,
            username=username or None,
            email=email,
            password_hash=password_hash,
            created_at=int(time.time()),
            updated_at=int(time.time()),
        )
    except Exception as e:
        return (
            ergonoti(message=f"Error al registrar usuario: {str(e)}", type="error"),
            register_form(),
        )
    print(f"redireccionando hacia {ROUTE_AFTER_REGISTER}")
    return Redirect(ROUTE_AFTER_REGISTER)


@rt.post
def login(session, email: str, password: str, important: str = ""):
    # si algún script/bot/ia llena el input "important" retorna vacío
    if len(important):
        return

    if session.get("auth"):
        return Redirect(logout)

    if not (len(email) and len(password)):
        return (
            ergonoti(message="Debe completar el formulario", type="warning"),
            login_form(),
        )

    else:
        print(f"verificando {email} en users")

        existing_user = _get_user_by_email(email)

        if existing_user and verify_password(password, existing_user.password_hash):
            session["auth"] = {
                "user_id": existing_user.id,
                "email": existing_user.email,
                "uuid": existing_user.uuid,
            }

            existing_user.last_login = int(time.time())
            db['auth_user'].update(existing_user)
            print (ROUTE_AFTER_LOGIN)
            print (session.get("tenant", "") + "/")
            return Redirect(ROUTE_AFTER_LOGIN + "@"+session.get("tenant", ""))
        else:
            return (
                ergonoti(message="Credenciales desconocidas", type="error"),
                login_form(),
            )


def _get_user_by_email(email: str):
    user_exists = None
    try:
        user_exists = auth_users("email=?", (email,), limit=1)
    except Exception as e:
        print(f"Error al buscar el usuario: {e}")

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

    Permite a los usuarios actualizar su correo electrónico y/o contraseña.
    Requiere la contraseña actual para verificación antes de realizar cambios.
    """
    # Asegurarse de que el usuario esté autenticado
    if "auth" not in session:
        print(session, "Debe iniciar sesión", "error")
        return Redirect(ROUTE_AFTER_LOGOUT)

    user = _get_user_by_email(session["auth"]["email"])
    if not user:
        print(session, "Usuario no encontrado", "error")
        return Redirect(ROUTE_AFTER_LOGOUT)

    # Verificar la contraseña actual si se proporcionó
    if current_password:
        if not verify_password(current_password, user.user_password_hash):
            print("Contraseña actual incorrecta", "error")
            return user_update_form(), ergonoti(
                message="Contraseña actual incorrecta", type="error"
            )
        # Actualizar la contraseña si se proporcionó una nueva y se confirmó
        elif len(new_password):
            if new_password != confirm_password:
                return user_update_form(), ergonoti(
                    message="Las contraseñas no coinciden", type="error"
                )
            else:
                new_password_hash = get_password_hash(new_password)

                # Guardar los cambios
                try:
                    users_tbl = db.t["auth_user"]
                    users_tbl.update(uuid=user.uuid, password_hash=new_password_hash)
                except Exception as e:
                    db.rollback()
                    print(session, f"Error al actualizar usuario: {str(e)}", "error")
                else:
                    print(session, "Contraseña actualizada correctamente", "success")

                    return user_update_form(), ergonoti(
                        message="Contraseña actualizada correctamente", type="success"
                    )

        else:
            return user_update_form(), ergonoti(
                message="La nueva contraseña no puede estar vacía", type="error"
            )


def user_template(content):
    return Div(
        Div(_id="notifications", _class="toast toast-top z-50"),
        Div(content, _id="auth-form-content"),
        # Div(
        #     "En mantención",
        #     _class="bg-red-600 fixed top-0 right-0 text-white font-bold italic justify-center rotate-z-45 translate-x-24 translate-y-24 w-100 p-2 text-center",
        #     _hx_trigger="load",
        #     _hx_on__load="console.log('cargando')",
        # ),
        _class="flex flex-col justify-center gap-8 items-center w-full min-h-screen bg-slate-700 dark:bg-slate-800 overflow-hidden",
    )


ROUTE_AFTER_LOGIN = "/"
ROUTE_AFTER_REGISTER = rt.rt_funcs.login
ROUTE_AFTER_LOGOUT = rt.rt_funcs.login
ROUTE_AFTER_UPDATE = rt.rt_funcs.profile

rt.to_app(app)
serve(port=8000)
