import sys
import uuid
import random
import string
import traceback
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache
from urllib.parse import urlencode
from core.helper import store_activity
from django.core.mail import send_mail
from django.utils.html import strip_tags
from rest_framework.response import Response
from django.utils.encoding import force_bytes
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from geoip2.database import Reader as GeoIP2Reader
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.middleware.csrf import CsrfViewMiddleware
from django.contrib.auth.tokens import default_token_generator


# -------------------------------
# Config
# -------------------------------

EXPIRY_MINUTES = 5
EXPIRE_IN = 8600 
MAX_ATTEMPTS = 5 
COOKIE_SECURE = True   
REMEMBER_ME_DAYS=30
COOKIE_HTTPONLY = True
ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
COOKIE_SAMESITE = "Lax"
COOLDOWN_MINUTES = 15


AUTH_SKIP_PATHS = {
    "/api/1.0/auth/login/",
    "/api/1.0/auth/token/refresh/",
    "/api/1.0/auth/logout/",
    "/api/1.0/auth/account/restore/",
    "/api/1.0/support/contact/create/",
    "/api/1.0/auth/login/2fa/",
    "/api/1.0/auth/resend/otp/",
    "/api/1.0/auth/resend-verification/",
    "/api/1.0/auth/password-reset-request/",   
    "/api/1.0/auth/verify-email/",
    "/api/1.0/auth/password-reset-confirm/",  
}

def generate_username(first_name, random_digit=6):
    """Generate unique username with random digits appended."""
    User = get_user_model()
    random_digits = ''.join(random.choices(string.digits, k=random_digit))
    username = f"{first_name.lower()}{random_digits}"

    while User.objects.filter(username=username).exists():
        random_digits = ''.join(random.choices(string.digits, k=random_digit))
        username = f"{first_name.lower()}{random_digits}"

    return username


def generate_otp(length=6):
    """Generate numeric OTP string."""
    return ''.join(random.choices(string.digits, k=length))


def send_otp_message(email, request):
    """Generate OTP, save hashed version, and send email."""
  
    try:
        validate_email(email)
    except ValidationError:
        raise ValueError("Invalid email address provided.")

    from .models import EmailOTP
    
    obj, created  = EmailOTP.objects.get_or_create(email=email)

    if created:
    # First-time OTP, just set it
        otp = generate_otp()
    else:
        # Existing OTP, check if allowed
        if not obj.can_request_new_otp():
            raise ValueError("You already have a valid OTP or are in cooldown. Please wait.")


    otp = generate_otp()

    request_ip = request.META.get("REMOTE_ADDR")

    obj.set_otp(otp, request_ip)

    # Render HTML template
    html_message = render_to_string("emails/otp_email.html", {
        "first_name": email,
        "otp": otp,  
        "app_name": "Note AI",
        "expiry_minutes": EXPIRY_MINUTES,
    })

    plain_message = strip_tags(html_message)

    send_mail(
        subject="Your OTP Code – noteaibackend",
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        html_message=html_message,
    )


def send_verification_email(request, user):
    """Send account verification email with UID + token."""

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    # Detect client type
    client_type = request.META.get("HTTP_X_CLIENT", "web").lower()

    if client_type == "mobile":
        # Example: Deep link for mobile app
        verification_url = (
            f"{settings.MOBILE_APP_DEEP_LINK_SCHEME}://verify-email?"
            f"{urlencode({'uid': uid, 'token': token})}"
        )
    else:
        # Default: Web SPA verification link
        verification_url = (
            f"{settings.FRONTEND_URL}/verify-email?"
            f"{urlencode({'uid': uid, 'token': token})}"
        )

    context = {
        "first_name": user.first_name,
        "app_name": getattr(settings, "APP_NAME", "Note AI"),
        "account_verification": verification_url,
    }

    html_message = render_to_string("emails/verify_email_confirm_mail.html", context)
    plain_message = strip_tags(html_message)

    send_mail(
        subject=f"Verify Your Email – {context['app_name']}",
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
    )

def send_password_reset_link(uid, raw_token, request, user):
    """
    Send password reset link with different handling for web vs mobile clients.
    """

    # Detect client type from headers or query params
    client_type = request.META.get("HTTP_X_CLIENT", "web").lower()
    # You can also check user-agent or add a query param like ?client=mobile

    # Construct reset URL depending on client
    if client_type == "mobile":
        # Example: Use deep link for mobile app
        reset_url = f"{settings.MOBILE_APP_DEEP_LINK_SCHEME}://password-reset?{urlencode({'uid': uid, 'token': raw_token})}"
    else:
        # Default: Web SPA link
        reset_url = f"{settings.FRONTEND_URL}/reset-password?{urlencode({'uid': uid, 'token': raw_token})}"


    context = {
        "reset_url": reset_url,
        "first_name": user.first_name,
        "user_email": user.email,
        "app_name": getattr(settings, "APP_NAME", "noteaibackend"),
        "support_email": getattr(settings, "SUPPORT_EMAIL", "eramarinfo@noteai.com"),
        "current_year": str(settings.CURRENT_YEAR) if hasattr(settings, "CURRENT_YEAR") else "2025",
        "site_url": settings.FRONTEND_URL,
        "expiry_minutes": EXPIRY_MINUTES,
    }

    html_message = render_to_string("emails/password_reset_link.html", context)
    plain_message = strip_tags(html_message)
    
    try:
        send_mail(
            subject=f"{context['app_name']} Password Reset Request",
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
        )
    except Exception as e:
        print(str(e))

def send_password_change_email(user):
    """Send password changed notification."""
    
    html_message = render_to_string("emails/password_changed.html", {
        "first_name": user.first_name,
        "app_name": "Note AI",
        "date": timezone.now().strftime("%B %d, %Y %H:%M"),
    })

    plain_message = strip_tags(html_message)

    send_mail(
        subject="Your password has been changed",
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
    )


def send_error_log(exc: Exception):
    """Send error logs to admin email."""
    exc_type, exc_value, exc_tb = sys.exc_info()
    stack_trace = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))

    html_message = render_to_string("emails/error_log.html", {
        "error_message": str(exc),
        "stack_trace": stack_trace,
        "app_name": getattr(settings, "APP_NAME", "noteaibackend"),
        "timestamp": timezone.now().strftime("%B %d, %Y %H:%M"),
        "server_name": getattr(settings, "SERVER_NAME", "Unknown"),
    })
    plain_message = strip_tags(html_message)

    admin_email = getattr(settings, "ADMIN_ERROR_REPORT_MANAGER", None)
    if admin_email:
        send_mail(
            subject=f"{settings.APP_NAME}: Error Report",
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin_email],
            html_message=html_message,
        )


# ------------------------------
# Brute force protection helpers
# ------------------------------

def get_client_ip(request):
    """Get client IP address from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')


def get_cache_key(request):
    return f"otp_ip_{get_client_ip(request)}"


def get_attempt_key(email):
    return f"otp_attempt_{email}"


def increment_failed_attempts(email, request):
    """Increment counters for both IP and email (safe version)."""
    ip_key = get_cache_key(request)
    email_key = get_attempt_key(email)

    ip_attempts = cache.get(ip_key, 0) + 1
    email_attempts = cache.get(email_key, 0) + 1

    cache.set(ip_key, ip_attempts, timeout=300)
    cache.set(email_key, email_attempts, timeout=300)

    return ip_attempts, email_attempts


def reset_failed_attempts(email, request):
    """Reset counters for IP and email after success."""
    cache.delete(get_cache_key(request))
    cache.delete(get_attempt_key(email))


def set_token_cookies(response: Response, access_token: str, refresh_token: str, remember_me: bool):
    """
    Set cookie attributes safely. For "remember me", persist cookies;
    otherwise session cookies (no max_age).
    """
    # Access token cookie
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=access_token,
        httponly=COOKIE_HTTPONLY,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
        max_age=REMEMBER_ME_DAYS * 24 * 3600 if remember_me else None,
    )
    # Refresh token cookie
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=refresh_token,
        httponly=COOKIE_HTTPONLY,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
        max_age=REMEMBER_ME_DAYS * 24 * 3600 if remember_me else None,
    )


def delete_token_cookies(response: Response):
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path="/")

def user_payload(user):
    # Keep payload lean; avoid heavy/unused fields
    return {
        "id": str(user.id),
        "email": user.email,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_email_verified": getattr(user, "is_email_verified", False),
        "is_active": user.is_active,
        "birth_date": user.birth_date,
        "gender": user.gender,
        "date_joined": user.date_joined,
        "bio": user.bio,
        "profile_picture": user.profile_picture.url if getattr(user, "profile_picture", None) else None,
        "is_user": user.is_user,
        "is_admin": user.is_admin,
        "is_staff": user.is_staff,
        "is_superuser": user.is_superuser,
        "country_code": user.country_code,
        "two_factor_enabled": user.two_factor_enabled,
        "language_preference": user.language_preference,
        "notification_preference": user.notification_preference,
        "is_permanent_disabled": user.is_permanent_disabled,
        "last_login": user.last_login,
    }

def enforce_csrf_if_web(request):
    """
    Enforce CSRF for session/cookie clients (browser).
    Skip for token/JWT-based API requests.
    """
    # Skip CSRF if Authorization header present
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") or auth_header.startswith("Token "):
        return None  

    # Instantiate CsrfViewMiddleware properly
    csrf_mw = CsrfViewMiddleware(get_response=lambda req: None)

    # Run CSRF check
    reason = csrf_mw.process_view(request, None, (), {})
    if reason is not None:
        return JsonResponse(
            {"error": "CSRF verification failed. Please refresh and try again."},
            status=403,
        )
    return None

def is_rate_limited_user(user_id, action: str, user_limit=5, window_seconds=60):
    """
    Rate limit actions (like OTP sends) per user.
    """
    key = f"rl:u:{action}:{user_id}"
    count = cache.get(key)

    if count is None:
        # First hit, initialize counter
        cache.set(key, 1, timeout=window_seconds)
        return False

    if count >= user_limit:
        return True

    cache.incr(key)
    return False


def is_rate_limited_ip(ip, action_key, ip_limit=20, window_seconds=3600):
    """
    Rate limit actions per IP.
    """
    key = f"rl:ip:{action_key}:{ip}"
    count = cache.get(key)

    if count is None:
        cache.set(key, 1, timeout=window_seconds)
        return False

    if count >= ip_limit:
        return True

    cache.incr(key)
    return False

def check_login_anomaly(request, user):
    
    ip = request.META.get("REMOTE_ADDR")
    try:
        with GeoIP2Reader(settings.MAXMIND_DB_PATH) as reader:
            rec = reader.city(ip)
            country = rec.country.name
    except Exception:
        country = None
    from .models import  UserActivity

    last = UserActivity.objects.filter(user=user, activity_type="login").order_by("-action_date_time").first()
    if last and last.geo_country and country and country != last.geo_country:
        # unusual geo
        reset_url = f'{settings.FRONTEND_URL}/dashboard/password-reset'
    
        ip_address = get_client_ip(request)

        html_message = render_to_string("emails/unusual_login.html", {
            "first_nam": user.first_name,
            "country": country,
            "last_login": last,
            "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M"),
            "ip_address": ip_address,
            "reset_password_url": reset_url,
            "app_name": "NoteAI",
        })

        plain_message = strip_tags(html_message)

        send_mail(
            subject="⚠️ Unusual Login Location Detected",
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
        )
    # store this login as activity
    store_activity(request, "login", user, {"country": country}, 200, True, "")



def send_account_deactive_mail(user):
    """Send password changed notification."""
    
    html_message = render_to_string("emails/account_deactive.html", {
        "first_name": user.first_name,
        "app_name": "Note AI",
        "date": timezone.now().strftime("%B %d, %Y %H:%M"),
    })

    plain_message = strip_tags(html_message)

    send_mail(
        subject="Your account has been deactivated.",
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
    )


def send_account_restore_mail(user):
    """Send password changed notification."""
    
    html_message = render_to_string("emails/account_restore.html", {
        "first_name": user.first_name,
        "app_name": "Note AI",
        "date": timezone.now().strftime("%B %d, %Y %H:%M"),
    })

    plain_message = strip_tags(html_message)

    send_mail(
        subject="Your account has been restored",
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
    )


def get_request_id(request):
    # allow upstream to pass a correlation id (e.g., from API gateway)
    return request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())




def send_primary_email_change(old_email:string, new_email:string, user):
    """Send password changed notification."""

    html_message = render_to_string("emails/email_change.html", {
        "first_name": user.first_name,
        "old_email":old_email,
        "new_email": new_email,
        "app_name": "Note AI",
        "date": timezone.now().strftime("%B %d, %Y %H:%M"),
    })

    plain_message = strip_tags(html_message)

    send_mail(
        subject="Your primary email has been changed",
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
    )