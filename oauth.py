"""Módulo OAuth para autenticación con Google usando fasthtml.oauth."""

import logging
import os
import time
import uuid as uuid_mod

from fasthtml.common import *
from fasthtml.oauth import GoogleAppClient

from auth.data.models import db

logger = logging.getLogger(__name__)

ROUTE_AFTER_LOGIN = "/admin/"

rt = APIRouter(prefix="/auth/oauth")

auth_users = db.t["auth_user"]
auth_identities = db.t["auth_identity"]

# Cliente OAuth de Google (built-in de FastHTML)
_client_id = os.getenv("GOOGLE_CLIENT_ID", "")
_client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
google_client = (
    GoogleAppClient(_client_id, _client_secret) if _client_id else None
)


def _get_redir_url(request) -> str:
    """Construye la redirect URI basándose en el request actual."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", request.url.netloc)
    return f"{scheme}://{host}/auth/oauth/google/callback"


@rt("/google/authorize", methods=["GET"])
def google_authorize(request, session):
    """Inicia el flujo OAuth redirigiendo a Google."""
    if not google_client:
        return Redirect("/auth/login")
    redir_url = _get_redir_url(request)
    login_url = google_client.login_link(redirect_uri=redir_url, state="google_oauth")
    return Redirect(login_url)


@rt("/google/callback", methods=["GET"])
def google_callback(request, session, code: str = "", error: str = ""):
    """Callback de Google OAuth. Intercambia code por token y establece sesión."""
    if error or not code or not google_client:
        return Redirect("/auth/login")

    redir_url = _get_redir_url(request)

    # Usar GoogleAppClient para intercambiar code y obtener userinfo
    try:
        info = google_client.retr_info(code, redirect_uri=redir_url)
    except Exception:
        logger.exception("Error al obtener info de Google OAuth")
        return Redirect("/auth/login")

    google_id = info.get("sub")
    email = info.get("email")
    name = info.get("name", "")
    email_verified = info.get("email_verified", False)

    if not google_id or not email or not email_verified:
        return Redirect("/auth/login")

    now = int(time.time())

    # Buscar identidad OAuth existente
    existing_identity = None
    try:
        results = auth_identities(
            "provider = ? AND external_id = ?", ("google", google_id), limit=1
        )
        if results:
            existing_identity = results[0] if isinstance(results, list) else results
    except Exception:
        pass

    if existing_identity:
        user = auth_users[existing_identity.auth_user_id]
    else:
        # Buscar auth_user por email
        user = None
        try:
            results = auth_users("email = ?", (email,), limit=1)
            if results:
                user = results[0] if isinstance(results, list) else results
        except Exception:
            pass

        if not user:
            user = auth_users.insert(
                username=name,
                email=email,
                password_hash=None,
                last_login=now,
                created_at=now,
                updated_at=now,
                is_active=1,
                uuid=uuid_mod.uuid4().hex,
            )

        # Vincular identidad Google al usuario
        auth_identities.insert(
            uuid=uuid_mod.uuid4().hex,
            auth_user_id=user.id,
            provider="google",
            external_id=google_id,
            external_email=email,
            external_name=name,
            created_at=now,
            updated_at=now,
            is_active=1,
        )

    user.last_login = now
    auth_users.update(user)

    # Establecer sesión (mismo patrón que login local)
    session["auth"] = {
        "user_id": user.id,
        "email": user.email,
        "uuid": user.uuid,
    }

    return Redirect(ROUTE_AFTER_LOGIN)
