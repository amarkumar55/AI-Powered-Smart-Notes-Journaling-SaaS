from django.utils.deprecation import MiddlewareMixin
from django_ratelimit.exceptions import Ratelimited
from django.http import JsonResponse

class RatelimitMiddleware(MiddlewareMixin):
    def process_exception(self, request, exception):
        if isinstance(exception, Ratelimited):
            return JsonResponse(
                {
                    "error": "Too many requests, slow down.",
                    "status_code": 429,
                },
                status=429,
            )
        return None  # let others bubble up

from urllib.parse import parse_qs
from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.conf import settings
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.sessions.models import Session

User = get_user_model()



@database_sync_to_async
def get_user_from_session(scope):
    """Get Django user from session cookie."""
    session_key = scope.get("cookies", {}).get(settings.SESSION_COOKIE_NAME)
    if not session_key:
        return AnonymousUser()
    try:
        session = Session.objects.get(session_key=session_key)
        uid = session.get_decoded().get("_auth_user_id")
        return User.objects.get(pk=uid)
    except Exception:
        return AnonymousUser()


@database_sync_to_async
def get_user_from_jwt(token: str):
    """Get Django user from JWT token."""
    try:
        validated_token = UntypedToken(token)
        return JWTAuthentication().get_user(validated_token)
    except Exception:
        return AnonymousUser()


class MultiAuthMiddleware(BaseMiddleware):
    """
    WebSocket authentication middleware:
    - JWT token from "Authorization" header (React Native)
    - JWT token from query string ?token=... (React Native fallback)
    - Django session cookie (Web)
    """

    async def __call__(self, scope, receive, send):
        # Default user
        scope["user"] = AnonymousUser()

        # --- Ensure cookies dict exists ---
        if "cookies" not in scope:
            headers = {k: v for k, v in scope.get("headers", [])}
            cookie_header = headers.get(b"cookie", b"").decode()
            cookies = {}
            for part in cookie_header.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies[k] = v
            scope["cookies"] = cookies

        # --- 1) JWT Authorization header ---
        headers = {k: v for k, v in scope.get("headers", [])}
        auth_header = headers.get(b"authorization", b"").decode()
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            scope["user"] = await get_user_from_jwt(token)

        # --- 2) JWT token in query string ---
        elif "query_string" in scope:
            qs = parse_qs(scope["query_string"].decode())
            token_list = qs.get("token")
            if token_list:
                scope["user"] = await get_user_from_jwt(token_list[0])

        # --- 3) Session cookie ---
        else:
            scope["user"] = await get_user_from_session(scope)

        return await super().__call__(scope, receive, send)