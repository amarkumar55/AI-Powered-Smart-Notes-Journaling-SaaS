
import logging

import secrets
from django.db import transaction
from rest_framework import status
from django.utils import timezone
from django.core.cache import cache
from datetime import datetime, time
from django.db.models import Subquery
from core.helper import store_activity
from apis.api_notes.models import Note
from rest_framework.views import APIView
from django.middleware.csrf import get_token
from rest_framework.response import Response
from django.utils.timezone import make_aware
from django.utils.dateparse import parse_date
from django.utils.encoding import force_bytes
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework.generics import ListAPIView
from django_ratelimit.decorators import ratelimit
from rest_framework.generics import RetrieveAPIView
from django.utils.http import urlsafe_base64_encode
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.files.images import get_image_dimensions
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import EmailOTP, Follow, WalletTransaction, UserActivity, Wallet
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken


from .utlity import  (
    send_verification_email, 
    send_otp_message, 
    get_cache_key,
    set_token_cookies, 
    delete_token_cookies, 
    user_payload,
    enforce_csrf_if_web, 
    MAX_ATTEMPTS, 
    EXPIRE_IN, 
    REFRESH_COOKIE,
    is_rate_limited_user,
    is_rate_limited_ip,
    check_login_anomaly,
    send_password_reset_link,
    send_password_change_email,
    send_account_deactive_mail,
    send_account_restore_mail,
    send_primary_email_change,
)

from .serializers import (
    RegisterSerializer, 
    LoginSerializer, 
    EmailVerificationSerializer,
    ResendEmailVerificationSerializer, 
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, 
    ChangePasswordSerializer,
    PasswordVerificationSerializer, 
    UserProfileSerializer,
    UpdateProfileSerializer,
    EmailOtpRequestSerializer, 
    EmailOtpVerifySerializer,
    AccountDeactivateSerializer,
    AccountRestoreSerializer,
    FollowSerializer, 
    UserPublicSerializer, 
    WalletSerializer, 
    WalletTransactionSerializer, 
    UserActivitySerializer,
    UserPublicProfileSerializer
)

User = get_user_model()

logger = logging.getLogger(__name__)

# -------------------------------
# Crsf token 
# -------------------------------
class CsrfBootstrapView(APIView):

    permission_classes = [AllowAny]

    def get(self, request):
        # This ensures a CSRF cookie is set and returns the token header value as well
        token = get_token(request)
        return Response({"csrfToken": token})
    

# -------------------------------
# Register
# -------------------------------
@method_decorator(ratelimit(key='user_or_ip', rate='3/m', block=True), name='dispatch')
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Minimal payload for mobile; web frontend can fetch profile later
        response_data = {
            "message": "Registration successful. Please check your email for verification.",
            "user": UserProfileSerializer(user).data,
        }

        return Response(response_data, status=status.HTTP_201_CREATED)
    
    
# -------------------------------
# Hybrid Login
# -------------------------------
@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
@method_decorator(csrf_exempt, name='dispatch') 
class HybridLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # CSRF only for web flows
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        serializer = LoginSerializer(data=request.data, context={'request': request})

        if not serializer.is_valid():
            
            return Response(
                {"success": False, "message": "Invalid credentials."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = serializer.validated_data['user']
        remember_me = bool(serializer.validated_data.get('remember_me', False))
        account_status = serializer.validated_data.get('account_status', 'active')
    
        check_login_anomaly(request, user)
    
        if account_status in ["inactive", "temporary_disabled", "permanent_disabled", "email_unverified"]:
            # Do not give tokens; just status
        
            return Response(
                
                {  
                   "success": False,
                   "message": "Account not active.",    
                   "status": account_status,
                   "email": user.email
                },
                
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        
        # If 2FA enabled, send OTP and stop here
        if user.two_factor_enabled:
            try:
                # Generic response to avoid enumeration details
                send_otp_message(user.email, request)
                return Response({
                    "message": "Two-factor authentication required.",
                    "requires_2fa": True,
                    "email": user.email
                }, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error("2FA OTP send error: %s", str(e))
                return Response({"error": "Failed to send verification code."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Issue tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        store_activity(request, "Logged Into Account", user, {}, 200, True, "")

        # Client type decides delivery
        client_type = request.headers.get("X-Client-Type", "web").lower()

        if client_type == "mobile":
            # Return in body (no cookies)
            return Response({
                "message": "Login successful.",
                "status": "active",
                "access_token": str(access),
                "refresh_token": str(refresh),
                "expiresIn": EXPIRE_IN,
                "user": user_payload(user)
            }, status=status.HTTP_200_OK)
        else:
            # Web: cookies only; do NOT include tokens in body
            response = Response({
                "message": "Login successful (cookie).",
                "status": "active",
                "expiresIn": EXPIRE_IN,
                "user": user_payload(user)
            }, status=status.HTTP_200_OK)

            set_token_cookies(response, str(access), str(refresh), remember_me)

            # Provide (new) CSRF token for subsequent requests
            response["X-CSRFToken"] = get_token(request)
            return response
        
# -------------------------------
# 2FA Verify / Complete Login
# -------------------------------
@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class HybridTwoFactorLoginView(APIView):
    
    permission_classes = [AllowAny]

    def post(self, request):
        # CSRF only for web flows
        maybe_csrf = enforce_csrf_if_web(request)

        if maybe_csrf is not None:
            return maybe_csrf

        email = (request.data.get('email') or "").strip().lower()
        otp_input = (request.data.get('otp') or "").strip()

        if not email or not otp_input:
            # Generic message to avoid enumeration
            return Response({"error": "OTP verification failed."}, status=status.HTTP_400_BAD_REQUEST)

        # Look up user (lean fields)
        user = User.objects.filter(email=email).only('id', 'email', 'two_factor_enabled',
                                                     'is_active', 'is_user', 'is_admin',
                                                     'is_staff', 'is_superuser').first()
        if not user:
            # Generic response; do not reveal existence
            return Response({"error": "OTP verification failed."}, status=status.HTTP_400_BAD_REQUEST)
        
        request_ip=request.META.get('REMOTE_ADDR')
        # Verify OTP
        email_otp = EmailOTP.objects.filter(email=email).first()
    
        if not email_otp or email_otp.is_expired() or not email_otp.verify_otp(otp_input, request_ip):
            # Clean up expired OTP if present
            if email_otp and email_otp.is_expired():
                email_otp.delete()
            return Response({"error": "OTP verification failed."}, status=status.HTTP_400_BAD_REQUEST)

        # Success → remove OTP
        email_otp.delete()

        # Issue tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        client_type = request.headers.get("X-Client-Type", "web").lower()
    
        if client_type == "mobile":
            response = Response({
                "message": "Login successful.",
                "status": "active",
                "access_token": str(access),
                "refresh_token": str(refresh),
                "expiresIn": access.lifetime.total_seconds(),
                "user": user_payload(user)
            }, status=status.HTTP_200_OK)
        else:
            response = Response({
                "message": "Login successful (2FA).",
                "status": "active",
                "expiresIn": access.lifetime.total_seconds(),
                "user": user_payload(user)
            }, status=status.HTTP_200_OK)
            # Respect remember_me from request if sent; default session cookies
            remember_me = bool(request.data.get("remember_me", False))
            set_token_cookies(response, str(access), str(refresh), remember_me)
            response["X-CSRFToken"] = get_token(request)

        store_activity(request, "Logged into account with 2FA", user, {}, 200, True, "")
        return response


# -------------------------------
# 2FA: Send OTP (Enumeration-safe)
# -------------------------------
@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class TwoFactorLoginOtpSend(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Always respond generically; try to send if user exists
        user = User.objects.filter(email=email).only('email').first()
        if user:
            try:
                send_otp_message(user.email, request)
            except Exception as e:
                # Log but do not disclose details to client
                logger.error("2FA OTP send error for %s: %s", email, str(e))

        return Response(
            {"message": "If the account exists, an OTP has been sent."},
            status=status.HTTP_200_OK
        )
    

# -------------------------------
# Refresh (Hybrid)
# -------------------------------
@method_decorator(ratelimit(key='user_or_ip', rate='2/m', block=True), name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class HybridTokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # CSRF only for web flows
        maybe_csrf = enforce_csrf_if_web(request)

        if maybe_csrf is not None:
            return maybe_csrf
        
        # Try body (mobile), then cookie (web)
        refresh_raw = request.data.get("refresh") or request.COOKIES.get(REFRESH_COOKIE)

        if not refresh_raw:
            raise InvalidToken("No refresh token provided.")

        try:
            old_refresh = RefreshToken(refresh_raw)
            user_id = old_refresh.get("user_id")
            if not user_id:
                raise InvalidToken("Malformed refresh token.")

            # Blacklist old refresh if possible
            try:
                old_refresh.blacklist()
            except Exception:
                # Blacklist app may be off; continue
                pass

            # Rotate: mint new refresh & access
            # Lean user fetch (only pk)
            user = User.objects.only('id').get(id=user_id)
            new_refresh = RefreshToken.for_user(user)
            new_access = new_refresh.access_token

            client_has_cookie = bool(request.COOKIES.get(REFRESH_COOKIE))

            if client_has_cookie:
                # Web: update cookies, don't leak tokens in body
                response = Response({"message": "Token refreshed via cookie."}, status=status.HTTP_200_OK)
                # Preserve "remember me" semantics by checking cookie max_age presence
                remember_me = True  # if a refresh cookie exists, we assume persistent login
                set_token_cookies(response, str(new_access), str(new_refresh), remember_me)
                return response
            else:
                # Mobile: return in body
                return Response({
                    "access_token": str(new_access),
                    "refresh_token": str(new_refresh),
                    "expiresIn": new_access.lifetime.total_seconds()
                }, status=status.HTTP_200_OK)

        except Exception:
            raise InvalidToken("Refresh token is invalid or expired.")



# -------------------------------
# Logout (Hybrid)
# -------------------------------
@method_decorator(ratelimit(key='user_or_ip', rate='10/m', block=True), name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class HybridLogoutView(APIView):
    """
    - Invalidates provided refresh (body or cookie).
    - Clears cookies (web).
    """
    permission_classes = [AllowAny]

    def post(self, request):
        # CSRF only for web flows
        maybe_csrf = enforce_csrf_if_web(request)

        if maybe_csrf is not None:
            return maybe_csrf
        
        user = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
        refresh_token = request.data.get("refresh") or request.COOKIES.get(REFRESH_COOKIE)

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                pass

        response = Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
        delete_token_cookies(response)

        if user:
            store_activity(request, "Logout from account", user, {}, 200, True, "")

        return response
    

    
# -------------------------------
# Email Verification
# -------------------------------

@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class EmailVerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        uidb64 = kwargs.get("uidb64")
        token = kwargs.get("token")

        serializer = EmailVerificationSerializer(
            data={},
            context={"request": request, "uuid": uidb64, "token": token}
        )

        if serializer.is_valid():
            try:
                serializer.save()
                return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error("Email verification error")
                return Response({"error": "Email verification failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"error": "Invalid verification request"}, status=status.HTTP_400_BAD_REQUEST)



# -------------------------------
# Resend Verification
# -------------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="3/m", block=True),name='dispatch')
class ResendEmailVerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
    
        serializer = ResendEmailVerificationSerializer(data=request.data, context={"request": request})

        # Always return generic success response to prevent enumeration
        if not serializer.is_valid():
            return Response({"message": "If this account exists, a verification email has been sent."},
                            status=status.HTTP_200_OK)

        user = serializer.validated_data.get("user")
        
        try:
            send_verification_email(request, user)  # consider async task
        except Exception:
            logger.error("Resend verification error")
        return Response({"message": "If this account exists, a verification email has been sent."},
                        status=status.HTTP_200_OK)
        

# -------------------------------
# Password Reset Request
# -------------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="3/m", block=True),name='dispatch')
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
    
        serializer = PasswordResetRequestSerializer(data=request.data, context={"request": request})

        if serializer.is_valid():
            user = serializer.validated_data.get("user")
        
            if user:
                try:
                    raw_token = secrets.token_urlsafe(32)
                    user.set_password_reset_token(token=raw_token, expiry_minutes=5)
                    uid = urlsafe_base64_encode(force_bytes(user.pk))
                    send_password_reset_link(uid, raw_token, request, user)
                    
                except Exception as e:
                    
                    logger.error("Password reset request error")

            # Always generic
            return Response({"message": "If an account with this email exists, a reset link has been sent."},
                            status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# -------------------------------
# Password Reset Confirm
# -------------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]


    def post(self, request, uidb64, token, *args, **kwargs):
    
        serializer = PasswordResetConfirmSerializer(
            data=request.data,
            context={"request": request, "uid": uidb64, "token": token}
        )

        if serializer.is_valid():
            user = serializer.validated_data["user"]
            new_password = serializer.validated_data["new_password"]

            try:
                with transaction.atomic():
                    user.set_password(new_password)
                    user.save()

                    # Invalidate all outstanding refresh tokens
                    OutstandingToken.objects.filter(user=user).delete()

                # ⚡ Offload email + activity log
                send_password_change_email(user)

                return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)

            except Exception as e:
                logger.error(f"Password reset confirm error: {str(e)}")
                return Response({"error": "Password reset failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# -------------------------
# 👤 User Profile
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def validate_file(self, file):
        """Validate uploaded profile picture"""
        max_size = 1 * 1024 * 1024  # 1MB
        if file.size > max_size:
            raise ValueError("File too large (max 1MB).")

        try:
            w, h = get_image_dimensions(file)
            if w > 2000 or h > 2000:
                raise ValueError("Image dimensions too large.")
        except Exception:
            raise ValueError("Invalid image file.")

    def get(self, request):
        serializer = UserProfileSerializer(request.user, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        # CSRF only for web flows
        maybe_csrf = enforce_csrf_if_web(request)

        if maybe_csrf is not None:
            return maybe_csrf
        
        # ✅ Validate file if present
        if "profile_picture" in request.FILES:
            try:
                self.validate_file(request.FILES["profile_picture"])
            except ValueError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UpdateProfileSerializer(
            request.user, data=request.data, partial=True, context={"request": request}
        )

        if serializer.is_valid():
            serializer.save()
            store_activity(
                request, "Profile updated", request.user, {}, 200, True, ""
            )
            return Response(
                {
                    "message": "Profile updated successfully.",
                    "user": UserProfileSerializer(
                        request.user, context={"request": request}
                    ).data,
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# -------------------------------
# Change Password (Authenticated)
# -------------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf
    
        serializer = ChangePasswordSerializer(data=request.data, user=request.user, context={"request": request})

        if serializer.is_valid():
            try:
                user = serializer.save()

                # ✅ Bulk invalidate refresh tokens
                OutstandingToken.objects.filter(user=user).delete()

                # ✅ Blacklist current access token
                try:
                    raw_token = request.auth
                    if raw_token:
                        token = AccessToken(raw_token)
                        BlacklistedToken.objects.get_or_create(
                            token=OutstandingToken.objects.get(jti=token["jti"])
                        )
                except Exception:
                    logger.warning("Access token blacklist failed")

                
                store_activity(request, "Password Changed", user, {}, 200, True, "")

                send_password_change_email(user)

                return Response(
                    {"message": "Password changed successfully. Please log in again.", "force_logout": True},
                    status=status.HTTP_200_OK,
                )
            

            except Exception as e:
                logger.error(f"Change password error: {str(e)}")
                return Response({"error": "Password change failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
# -------------------------
# 🔒 Password Verification
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class PasswordVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # ✅ Enforce CSRF for web clients
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        serializer = PasswordVerificationSerializer(
            data=request.data, user=request.user, context={"request": request}
        )

        if serializer.is_valid():
            return Response(
                {"message": "Password verified successfully."},
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# -------------------------
# ✉️ Change Email - Request OTP
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class ChangeEmailRequestOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
    
        ip = request.META.get("REMOTE_ADDR")
        
        if is_rate_limited_user(request.user.id, "otp_send", user_limit=5, window_seconds=60):
            return Response({"error":"Too many OTP requests, wait a minute."}, status=429)
        if is_rate_limited_ip(ip, "otp_send", ip_limit=20, window_seconds=3600):
            # Consider returning CAPTCHA required, or generic 429
            return Response({"error":"Too many requests from this IP."}, status=429)


        serializer = EmailOtpRequestSerializer(data=request.data, context={"request": request})

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        old_email = serializer.validated_data["old_email"]
        new_email = serializer.validated_data["new_email"]

        if request.user.email != old_email:
            return Response(
                {"error": "Old email does not match your account."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(email=new_email).exists():
            return Response(
                {"error": "Email is already linked with another account."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cooldown_key = get_cache_key(request)

        if cache.get(cooldown_key):
            return Response(
                {"error": "Please wait before requesting OTP again."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            # ✅ Only send OTP to old email first
            send_otp_message(old_email, request)
            send_otp_message(new_email, request)

        
            cache.set(f"pending_new_email:{request.user.id}", new_email, timeout=600)
            cache.set(cooldown_key, True, timeout=60)

            return Response(
                {"message": "OTP sent to emails. Please verify before proceeding."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error sending OTP for email change: {str(e)}")
            return Response(
                {"error": "Failed to send OTP."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# -------------------------
# ✉️ Change Email - Verify OTP
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class ChangeEmailVerifyOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # ✅ Enforce CSRF for web clients
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf
        
        serializer = EmailOtpVerifySerializer(data=request.data, context={"request": request})

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        old_email = serializer.validated_data["old_email"]
        new_email = serializer.validated_data["new_email"]
        old_email_otp = serializer.validated_data["old_email_otp"]
        new_email_otp = serializer.validated_data["new_email_otp"]

        if request.user.email != old_email:
            return Response(
                {"error": "Old email does not match your account."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cached_new_email = cache.get(f"pending_new_email:{request.user.id}")
    
        if not cached_new_email or cached_new_email != new_email:
            return Response(
                {"error": "New email verification request not found or expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        attempt_key = f"user_attempts:{request.user.id}"
        attempts = cache.get(attempt_key, 0)

        if attempts >= MAX_ATTEMPTS:
            return Response(
                {"error": "Too many invalid attempts. Try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        try:
            old_otp = EmailOTP.objects.get(email=old_email)
            new_otp = EmailOTP.objects.get(email=new_email)
        except EmailOTP.DoesNotExist:
            return Response(
                {"error": "Invalid Otps."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        
        if old_otp.is_expired() or new_otp.is_expired():
            return Response(
                {"error": "One or both OTPs have expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        

        request_ip=request.META.get('REMOTE_ADDR')

        if old_otp.verify_otp(old_email_otp, request_ip) and new_otp.verify_otp(new_email_otp, request_ip):
            with transaction.atomic():
                request.user.email = new_email
                request.user.save()

                old_otp.delete()
                new_otp.delete()
                cache.delete(attempt_key)
                cache.delete(f"pending_new_email:{request.user.id}")
                send_primary_email_change(old_email, new_email, request.user)
                store_activity(
                    request,
                    "Changed email",
                    request.user,
                    {"new_email": new_email, "old_email": old_email},
                    200,
                    True,
                    "",
                )

            return Response(
                {"message": "Email updated successfully."},
                status=status.HTTP_200_OK,
            )

        cache.set(attempt_key, attempts + 1, 600)
        return Response({"error": "Invalid OTP(s)."}, status=status.HTTP_400_BAD_REQUEST)


# -------------------------
# 🛑 Account Deactivate
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class AccountDeactivateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
    
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        serializer = AccountDeactivateSerializer(
            data=request.data, context={"request": request, "user": request.user}
        )
        
        serializer.is_valid(raise_exception=True)

        user = request.user
        try:
            user.is_active = False
            user.deactivated_at = timezone.now()
            user.save()

            send_account_deactive_mail(user)

    
            return Response(
                {"message": "Account deactivated. Will be permanently deleted after 30 days if not restored."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Account deactivation error: {str(e)}")
            return Response(
                {"error": "Failed to deactivate account."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )



# -------------------------
# 🛑 Account Restore
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class AccountRestoreView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # ✅ CSRF for web
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf
        
        serializer = AccountRestoreSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        try:
            user.is_active = True
            user.deactivated_at = None
            user.save()

            send_account_restore_mail(user)

            return Response(
                {"message": "Account restored. You can now log in."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Account restore error: {str(e)}")
            return Response(
                {"error": "Failed to restore account."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# -------------------------
# Follow user view
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class FollowUserView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        # ✅ CSRF for web
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf
        
        if not user_id:
            return Response({"error": "Invalid request."}, status=status.HTTP_400_BAD_REQUEST)
        
        """Follow another user"""
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if target_user == request.user:
            return Response({"error": "You cannot follow yourself."}, status=status.HTTP_400_BAD_REQUEST)

        # Example privacy check (uncomment if required)
        # if not target_user.profile.is_public and target_user != request.user:
        #     return Response({"error": "This profile is private."}, status=403)

        with transaction.atomic():
            follow, created = Follow.objects.get_or_create(
                follower=request.user, following=target_user
            )

        if not created:
            return Response({
                "message": "Already following this user.",
                "data": FollowSerializer(follow).data
            }, status=status.HTTP_200_OK)

        # Log the follow activity
        store_activity(request, "Followed user", request.user, {"following": target_user.username}, 200, True, "")

        return Response({
            "message": "Followed successfully.",
            "data": FollowSerializer(follow).data
        }, status=status.HTTP_201_CREATED)


# -------------------------
# UnFollow user view
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class UnfollowUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf
    
        """Unfollow a user"""
        try:
            follow = Follow.objects.get(follower=request.user, following_id=user_id)
        except Follow.DoesNotExist:
            return Response({"error": "You are not following this user."}, status=status.HTTP_400_BAD_REQUEST)

        target_user = follow.following
        with transaction.atomic():
            follow.delete()

        # Log the unfollow activity
        store_activity(request, "Unfollowed user", request.user, {"unfollowed": target_user.username}, 200, True, "")

        return Response({"message": "Unfollowed successfully."}, status=status.HTTP_200_OK)


# -------------------------
# Follower List View
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class FollowersListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserPublicSerializer

    def get_queryset(self):
        user_id = self.request.user.id 

        follower_ids = Follow.objects.filter(following_id=user_id).values("follower_id")
    
        qs = (User.objects
              .filter(id__in=Subquery(follower_ids))
              .only("id","username","first_name","last_name","profile_picture")
              .order_by("first_name","last_name"))

        search = self.request.query_params.get("search")
        if search:
            vector = SearchVector("first_name", "last_name", config="simple")
            query  = SearchQuery(search, config="simple")
            qs = qs.annotate(rank=SearchRank(vector, query)) \
                   .filter(rank__gt=0.0) \
                   .order_by("-rank","first_name","last_name")

        return qs  

# -------------------------
# Following List View
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name="dispatch")
class FollowingListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserPublicSerializer  # default

    def get_queryset(self):
        user_id = self.request.user.id 

        following_ids = Follow.objects.filter(follower_id=user_id).values("following_id")
    
        qs = (User.objects
              .filter(id__in=Subquery(following_ids))
              .only("id", "username", "first_name", "last_name", "profile_picture")
              .order_by("first_name", "last_name"))

        search = self.request.query_params.get("search")
        if search:
            vector = SearchVector("first_name", "last_name", config="simple")
            query = SearchQuery(search, config="simple")
            qs = qs.annotate(rank=SearchRank(vector, query)) \
                   .filter(rank__gt=0.0) \
                   .order_by("-rank", "first_name", "last_name")

        return qs

    def list(self, request, *args, **kwargs):
        only_ids = request.query_params.get("only_ids")
        if only_ids and only_ids.lower() in ["1", "true", "yes"]:
            # return only list of ids
            user_id = request.user.id 
            following_ids = Follow.objects.filter(follower_id=user_id).values_list("following_id", flat=True)
            return Response(list(following_ids))
        
        # default full serializer
        return super().list(request, *args, **kwargs)
    
# -------------------------
# Wallet Balance View
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class WalletBalanceView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WalletSerializer

    def get(self, request):
        wallet, _ = Wallet.objects.get_or_create(user=request.user)
        serializer = self.serializer_class(wallet)
        return Response(serializer.data)

# -------------------------
# Wallet Transactions View
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class WalletTransactionsView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WalletTransactionSerializer

    def get_queryset(self):
        wallet = get_object_or_404(Wallet, user=self.request.user)
        qs = WalletTransaction.objects.filter(wallet=wallet)

        # ✅ Filter by transaction type (must be indexed enum/choice field)
        txn_type = self.request.query_params.get("type")  # expected: "credit" or "debit"
        if txn_type in ["credit", "debit"]:
            qs = qs.filter(type=txn_type)

        # ✅ Indexed datetime filtering
        start_date = self.request.query_params.get("start_date")
        end_date = self.request.query_params.get("end_date")

        if start_date:
            dt = make_aware(datetime.combine(parse_date(start_date), time.min))
            qs = qs.filter(created_at__gte=dt)
        if end_date:
            dt = make_aware(datetime.combine(parse_date(end_date), time.max))
            qs = qs.filter(created_at__lte=dt)

        return qs.select_related("wallet").order_by("-created_at")
    


# -------------------------
# User Activities View
# -------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class UserActivityView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserActivitySerializer

    def get_queryset(self):
        qs = UserActivity.objects.filter(user=self.request.user)

        search = self.request.query_params.get("search")
        if search:
            vector = SearchVector("activity_type", config="simple")
            query  = SearchQuery(search, config="simple")
            qs = qs.annotate(rank=SearchRank(vector, query)).filter(rank__gt=0.0).order_by("-rank", "-action_date_time")

        start_date = self.request.query_params.get("start_date")
        end_date   = self.request.query_params.get("end_date")

        if start_date:
            dt = make_aware(datetime.combine(parse_date(start_date), time.min))
            qs = qs.filter(action_date_time__gte=dt)
        if end_date:
            dt = make_aware(datetime.combine(parse_date(end_date), time.max))
            qs = qs.filter(action_date_time__lte=dt)

        # fields-only projection if serializers don't need everything
        return qs.only(
            'activity_type', 'geo_country', 'geo_city', 'user_agent', 'browser',
                   'browser_version','os', 'os_version', 'device_type', 'device_brand',
                   'device_model', 'action_date_time'
        ).order_by("-action_date_time")



@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class PublicProfileView(RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserPublicProfileSerializer
    lookup_field = "username"  # we’ll search user by username, not pk
    queryset = User.objects.all().only("id", "username", "first_name", "last_name", "profile_picture")

    def retrieve(self, request, *args, **kwargs):
        username = kwargs.get("username")
        user = get_object_or_404(self.get_queryset(), username=username)

        # count only published notes
        notes_count = Note.objects.filter(user=user, is_publish=True).count()
        user.notes_count = notes_count  # attach dynamically

        serializer = self.get_serializer(user)
        return Response(serializer.data)
    


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')  # Conditional CSRF for web
class BlockUserFromFollow(APIView): 
    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        admin_user = request.user  # the logged-in user

        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        # check if target_user is following admin_user
        follow_relation = Follow.objects.filter(
            follower=target_user,   # target_user is the follower
            following=admin_user    # admin_user is the one being followed
        ).first()

        if not follow_relation:
            return Response({"error": "This user is not following you."}, status=status.HTTP_400_BAD_REQUEST)

        # remove the relation (block)
        follow_relation.delete()

        # Log the block activity
        store_activity(
            request,
            "Blocked user (removed follower)",
            admin_user,
            {"blocked_user": target_user.username},
            200,
            True,
            ""
        )

        return Response(
            {"message": "User removed from your followers successfully."},
            status=status.HTTP_200_OK
        )