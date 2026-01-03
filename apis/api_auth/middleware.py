import re
import time
import logging
from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from django.middleware.csrf import CsrfViewMiddleware
from rest_framework.exceptions import AuthenticationFailed
from apis.api_auth.utlity import get_client_ip, AUTH_SKIP_PATHS
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError




User = get_user_model()

logger = logging.getLogger(__name__)



class APIRateLimitMiddleware(MiddlewareMixin):
    """
    Simple per-IP rate limiting middleware for API endpoints
    """

    RATE_LIMITS = {
        r"/api/1.0/auth/register": {"limit": 5, "window": 60},     # 5 per minute
        r"/api/1.0/auth/login": {"limit": 10, "window": 60},       # 10 per minute
        r"/api/1.0/auth/password-reset": {"limit": 3, "window": 60}, 
        r"/api/1.0/auth/verify-email": {"limit": 10, "window": 60},
    }

    def process_request(self, request):
        # Only apply to API endpoints
        
        if not  request.path.startswith("/api/"):
            return None

        client_ip = get_client_ip(request)
        user_part = f":u{request.user.id}" if request.user and request.user.is_authenticated else ""

        for pattern, rule in self.RATE_LIMITS.items():
            if re.match(pattern, request.path):
                cache_key = f"rl:{client_ip}{user_part}:{pattern}"
                requests = cache.get(cache_key, 0)

                if requests >= rule["limit"]:
                    return JsonResponse(
                        {"error": "Rate limit exceeded. Please try again later."},
                        status=429,
                    )

                cache.set(cache_key, requests + 1, rule["window"])
                break

        return None



class APIRequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log API requests for monitoring and debugging
    """
    
    def process_request(self, request):
        # Only log API requests
        if request.path.startswith('/api/'):
            request.start_time = time.time()
        
        return None
    
    def process_response(self, request, response):
        # Only log API responses
        if hasattr(request, 'start_time') and request.path.startswith('/api/'):
            duration = time.time() - request.start_time
            
            # Log API request details
            log_data = {
                'path': request.path,
                'method': request.method,
                'status_code': response.status_code,
                'duration': round(duration, 3),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'ip': get_client_ip(request),
            }
            
            if hasattr(request, 'user') and request.user.is_authenticated:
                log_data['user_id'] = request.user.id
                log_data['user_email'] = request.user.email
            
            logger.info(f"API Request: {log_data}")
        
        return response
    


class APISecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers to API responses
    """
    
    def process_response(self, request, response):
        # Only apply to API responses
        if request.path.startswith('/api/'):
            # Add security headers
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            response['X-XSS-Protection'] = '1; mode=block'
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
        
        return response 
    

class CookieOrHeaderJWTAuthentication(JWTAuthentication):
    """
    Hybrid JWT Authentication:
    - Header (Bearer) for mobile/clients.
    - HttpOnly 'access_token' cookie for web.
    - CSRF enforced only for unsafe methods *after* successful cookie auth.
    - Never block AllowAny endpoints (login/refresh/logout) due to stale cookies.
    """

    SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

    def authenticate(self, request):
        # 0) Skip auth entirely for auth endpoints
        #    (prevents stale/invalid cookies from breaking login/refresh/logout)
        if request.path in AUTH_SKIP_PATHS or any(request.path.startswith(p) for p in AUTH_SKIP_PATHS):
            return None

        # 1) Try Authorization header first
        header = self.get_header(request)
        if header is not None:
            # if header token is bad, we *do* want to raise (standard behavior)
            return super().authenticate(request)

        # 2) Fallback to cookie
        raw_token = request.COOKIES.get("access_token")  # keep name consistent
        if not raw_token:
            return None

        # Validate cookie token; if bad, DON'T raise — let AllowAny views proceed
        try:
            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)
        except (InvalidToken, TokenError):
            return None  # <- critical: don't block login/refresh/etc.

        # 3) Only now enforce CSRF for unsafe methods
        if request.method not in self.SAFE_METHODS:
            csrf_check = CsrfViewMiddleware(lambda r: None)
            reason = csrf_check.process_view(request, None, (), {})
            if reason is not None:
                # At this point we *are* authenticating via cookie, so CSRF must pass
                raise AuthenticationFailed("CSRF token missing or incorrect.")

        return (user, validated_token)



class ConditionalCSRFMiddleware(MiddlewareMixin):
    """
    ✅ Enforce CSRF for session/cookie (browser) clients.
    ❌ Skip CSRF for token/JWT (API/mobile) clients.
    """

    def __init__(self, get_response=None):
        super().__init__(get_response)  # ✅ Call parent initializer
        self.csrf_middleware = CsrfViewMiddleware(get_response)

    def process_view(self, request, callback, callback_args, callback_kwargs):
        # Skip CSRF for safe HTTP methods
        if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return None

        # Skip CSRF if using token/JWT auth
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") or auth_header.startswith("Token "):
            return None  

        # Otherwise enforce CSRF (browser clients)
        response = self.csrf_middleware.process_view(
            request, callback, callback_args, callback_kwargs
        )
        if response is not None:
            return JsonResponse(
                {"error": "CSRF verification failed. Please refresh and try again."},
                status=403,
            )
        return None



