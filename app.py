import bcrypt

from components import *
from fasthtml.common import *

APP_NAME = "User Auth"

rt = APIRouter(prefix="/auth")
app = FastHTML(title=APP_NAME, theme="dark", favicon="favicon.ico")
db = database("auth.db")
class Users:
    id: int
    username: str
    email: str
    rut: str
    password_hash: str

users = db.create(Users)

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
        return Redirect("/")
    except KeyError:
        return Redirect("/auth/login")


def user_profile_form():
    return Form(
        H2(
            "Actualizar datos de usuario",
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
        Div(cls="text-center mb-8")(
            Span(
                I(_class="fa fa-solid fa-camera"),
                "Archivo Gala 4MB 2025",
                cls="text-md text-wrap xl:text-2xl md:text-3xl xl:text-5xl font-bold text-slate-600 dark:text-white mb-2",
            ),
            P(
                "Más info en el Whatsapp de apoderados",
                cls="text-md lg:text-lg opacity-70 text-slate-400",
            ),
        ),
        Form(
            H1(
                I(_class="fas fa-user-circle mr-2"),
                "Iniciar Sesión",
                _class="text-2xl font-bold mb-4",
            ),
            Input(
                id="nombre",
                name="nombre",
                placeholder="nombre",
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


@rt
def index():
    """Muestra el formulario de inicio de sesión."""
    return user_template(login_form())
    #return "aoeuaoeu"


@rt.post
def login(session, nombre: str, password: str, important: str = ""):
    # si algún script/bot/ia llena el input "important" retorna vacío
    if len(important):
        return
    print(session)
    if session.get("toasts"):
        del session["toasts"]
    if not (len(nombre) and len(password)):
        return toast_notification(
            message="Debe completar el formulario", type="warning"
        ), login_form()

    else:
        print(f"verificando nombre {nombre} en alumnos")

        try:
            exist_alumno = alumno[nombre]
        except NotFoundError:
            return toast_notification(
                message="Credenciales desconocidas", type="error"
            ), login_form()

        except Exception as e:
            print(f"Error al buscar el usuario: {e}")
        else:
            print("verificando password")
            if exist_alumno and verify_password(password, alumno[nombre].password_hash):
                session["auth"] = {"alumno_id": alumno[nombre].id, "name": nombre}
                add_toast(session, f"Sesión iniciada como {nombre}", "success")
                return Redirect("/")
            else:
                return toast_notification(
                    message="Credenciales desconocidas", type="error"
                ), login_form()


@rt
def profile():
    return user_profile_form()


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
        return Redirect(login)

    alumno_id = session["auth"]["alumno_id"]

    # Obtener el usuario actual
    # alumno = db.q("select * from alumno where id = ?", (alumno_id,))[0]
    alumnos = db.t["alumno"]
    alumno = alumnos("id=?", (alumno_id,))[0]
    if not alumno:
        print(session, "Usuario no encontrado", "error")
        return Redirect(login)

    user_name = alumno.nombre
    user_password_hash = alumno.password_hash

    # Verificar la contraseña actual si se proporcionó
    if current_password:
        if not verify_password(current_password, user_password_hash):
            print("Contraseña actual incorrecta", "error")
            return user_profile_form(), toast_notification(
                message="Contraseña actual incorrecta", type="error"
            )
        # Actualizar la contraseña si se proporcionó una nueva y se confirmó
        elif len(new_password):
            if new_password != confirm_password:
                return user_profile_form(), toast_notification(
                    message="Las contraseñas no coinciden", type="error"
                )
            else:
                new_password_hash = get_password_hash(new_password)

                # Guardar los cambios
                try:
                    alumnos.update(nombre=user_name, password_hash=new_password_hash)
                except Exception as e:
                    db.rollback()
                    print(session, f"Error al actualizar usuario: {str(e)}", "error")
                else:
                    print(session, "Contraseña actualizada correctamente", "success")

                    return user_profile_form(), toast_notification(
                        message="Contraseña actualizada correctamente", type="success"
                    )

        else:
            return user_profile_form(), toast_notification(
                message="La nueva contraseña no puede estar vacía", type="error"
            )


def user_template(content):
    return Div(
        # Div("En mantención", _class="bg-red-600 text-white font-bold italic justify-center w-full text-center", _hx_trigger="load", _hx_on__load="console.log('cargando')"),
        Div(_id="notifications", _class="toast toast-top z-50"),
        Div(content, _id="auth-form-content"),
        _class="flex flex-col justify-center gap-8 items-center w-full min-h-screen bg-slate-700 dark:bg-slate-800",
    )



rt.to_app(app)
serve(port=8000)
