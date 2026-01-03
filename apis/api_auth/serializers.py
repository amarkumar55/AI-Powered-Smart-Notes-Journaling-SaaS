import re
from datetime import date
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from core.helper import store_activity
from rest_framework import serializers
from django.utils.html import strip_tags
from django.utils.encoding import force_str
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import default_token_generator
from .models import Follow, Wallet, WalletTransaction, UserActivity
from apis.api_auth.utlity import generate_username, send_verification_email


User = get_user_model()

# ---------------------------
# Helpers
# ---------------------------
def normalize_email(value: str) -> str:
    return (value or "").strip().lower()

def validate_password_strength(password: str):
    """Strong password validation"""
    if len(password) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        raise serializers.ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        raise serializers.ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        raise serializers.ValidationError("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        raise serializers.ValidationError("Password must contain at least one special character.")
    return password


# ---------------------------
# Registration
# ---------------------------
class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    is_accepted_terms = serializers.BooleanField(required=True)
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'birth_date', 'gender',
            'email', 'password', 'confirm_password', 'is_accepted_terms'
        ]
        extra_kwargs = {
            'first_name': {'min_length': 2, 'max_length': 30},
            'last_name': {'min_length': 2, 'max_length': 30},
            'birth_date': {'required': True},
            'gender': {'required': True},
            'email': {'required': True},
        }

    def validate_email(self, value):
        email = normalize_email(value)
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return email

    def validate_birth_date(self, value):
        today = date.today()
        age = today.year - value.year - ((today.month, today.day) < (value.month, value.day))
        if age < 13:
            raise serializers.ValidationError("You must be at least 13 years old to register.")
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        if not attrs.get('is_accepted_terms'):
            raise serializers.ValidationError("You must accept the terms and conditions.")
        validate_password_strength(attrs['password'])
        return attrs

    def create(self, validated_data):
        validated_data['email'] = normalize_email(validated_data['email'])
        validated_data.pop('confirm_password')
        validated_data.pop('is_accepted_terms')

        username = generate_username(validated_data.get('first_name'))

        user = User(
            email=validated_data['email'],
            username=username,
            first_name=validated_data['first_name'].strip(),
            last_name=validated_data['last_name'].strip(),
            birth_date=validated_data['birth_date'],
            gender=validated_data['gender'],
            is_accepted_terms=True,
            is_active=False,
            is_email_verified=False,
            date_joined=timezone.now(),
            last_login=timezone.now(),
        )
        user.set_password(validated_data['password'])
        user.save()

        try:
            send_verification_email(self.context['request'], user)
        except Exception as e:
            print(str(e))
        
        return user


# ---------------------------
# Login
# ---------------------------
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    remember_me = serializers.BooleanField(default=False, required=False)

    def validate(self, attrs):
        email = normalize_email(attrs.get('email'))
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError("Email and password are required.")

        try:        
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials.")

        if getattr(user, "is_permanent_disabled", False):
            attrs['account_status'] = "permanent_disabled"
            attrs['user'] = user
            return attrs

        if not user.is_active:
            attrs['account_status'] = "inactive"
            attrs['user'] = user
            return attrs

        # Authenticate with 
    
        user = authenticate(self.context.get('request'), username=user.email, password=password)
    
        if not user:
            raise serializers.ValidationError({"detail": "Invalid credentials."})

        if not user.is_email_verified:
            attrs['account_status'] = "email_unverified"
            attrs['user'] = user
            return attrs

        attrs['account_status'] = "active"
        attrs['user'] = user
        return attrs


# ---------------------------
# Email Verification
# ---------------------------
class EmailVerificationSerializer(serializers.Serializer):
    def validate(self, attrs):
        uidb64 = self.context.get('uuid')
        token = self.context.get('token')

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            raise serializers.ValidationError("Invalid verification link.")

        if not default_token_generator.check_token(user, token):
            raise serializers.ValidationError("Invalid or expired verification link.")

        if user.is_email_verified:
            raise serializers.ValidationError("Email is already verified.")

        attrs['user'] = user
        return attrs

    def save(self):
        user = self.validated_data['user']
        user.is_email_verified = True
        user.is_active = True
        user.save(update_fields=["is_email_verified", "is_active"])
        return user


# ---------------------------
# Resend Email Verification
# ---------------------------
class ResendEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = normalize_email(attrs.get("email"))
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "Email sent!, Please check your mail box."})
        if user.is_email_verified:
            raise serializers.ValidationError({"email": "This account is already verified."})
        attrs["user"] = user
        attrs["email"] = email
        return attrs


# ---------------------------
# Password Reset (Request + Confirm)
# ---------------------------
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = normalize_email(attrs.get("email"))
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = None
            raise serializers.ValidationError({"email": "Email sent!, Please check your mail box."})
        attrs['user'] = user  # Do not disclose existence to client
        attrs['email'] = email
        return attrs
        

class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        uidb64 = self.context.get("uid")
        token = self.context.get("token")

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            raise serializers.ValidationError({"token": "Invalid reset link."})

    
        if not user.verify_password_reset_token(token):
            raise serializers.ValidationError({"token": "Invalid or expired token."})

        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})

        validate_password_strength(attrs["new_password"])

        attrs["user"] = user
        return attrs

    def save(self):
        
        user = self.validated_data["user"]
        new_password = self.validated_data["new_password"]
        user.set_password(new_password)
        user.updated_at = timezone.now()

        user.clear_password_reset_token()
        user.save(update_fields=["password", "updated_at", "password_reset_token", "password_reset_expires_at"])

        store_activity(
            self.context["request"],
            "Password reset",
            user,
            {},
            200,
            True,
            "",
        )
        return user


# ---------------------------
# Change Password
# ---------------------------
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, min_length=8, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def validate_old_password(self, value):
        if not self.user or not self.user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("New passwords do not match.")
        validate_password_strength(attrs['new_password'])
        if self.user.check_password(attrs['new_password']):
            raise serializers.ValidationError("New password cannot be the same as the old password.")
        return attrs

    def save(self):
        new_password = self.validated_data["new_password"]
        self.user.set_password(new_password)
        self.user.updated_at = timezone.now()
        self.user.save(update_fields=["password", "updated_at"])
        store_activity(self.context["request"],"Password changed", self.user, {}, 200, True, "")
        return self.user


# ---------------------------
# Password Verification
# ---------------------------
class PasswordVerificationSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def validate(self, data):
        if not self.user:
            raise serializers.ValidationError("User context is required.")
        if not self.user.check_password(data['password']):
            raise serializers.ValidationError("Incorrect password.")
        return data


# ---------------------------
# User Profile
# ---------------------------
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:

        model = User
        
        fields = [
            'first_name', 
            'last_name',
            'email', 
            'is_email_verified',
            'username', 
            'birth_date', 
            'gender',
            'date_joined',
            'is_superuser',
            'is_admin',
            'is_staff',
            'is_user',
            'country_code', 
            'state_code',
            'city',
            'profile_picture', 
            'language_preference', 
            'notification_preference', 
            'bio',
            'is_permanent_disabled',
            'two_factor_enabled', 
            'is_active',
            'last_login',
            'followers_count',
            'following_count',
        ]
    
        read_only_fields = [ 
            'email', 
            'username', 
            'is_email_verified', 
            'date_joined', 
            'is_active',
            'last_login',
            'is_superuser',
            'is_admin',
            'is_staff',
            'is_user',
            'is_permanent_disabled'
        ]


class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'first_name', 
            'last_name', 
            'profile_picture', 
            'bio', 
            'gender', 
            'username',
            'country_code', 
            'birth_date', 
            'language_preference', 
            'notification_preference',
        ]

    def validate_first_name(self, value):
        if not value or len(value.strip()) < 2:
            raise serializers.ValidationError("First name must be at least 2 characters long.")
        return value.strip()

    def validate_last_name(self, value):
        if not value or len(value.strip()) < 2:
            raise serializers.ValidationError("Last name must be at least 2 characters long.")
        return value.strip()


# ---------------------------
# 2FA
# ---------------------------
class TwoFactorSetupSerializer(serializers.Serializer):
    enable_2fa = serializers.BooleanField(required=True)


# ---------------------------
# Logout
# ---------------------------
class LogoutSerializer(serializers.Serializer):
    pass


# ---------------------------
# Email OTP (Change Email)
# ---------------------------
class EmailOtpRequestSerializer(serializers.Serializer):
    old_email = serializers.EmailField(required=True)
    new_email = serializers.EmailField(required=True)


class EmailOtpVerifySerializer(serializers.Serializer):
    old_email = serializers.EmailField(required=True)
    new_email = serializers.EmailField(required=True)
    old_email_otp = serializers.CharField(required=True, min_length=6, max_length=6)
    new_email_otp = serializers.CharField(required=True, min_length=6, max_length=6)


# ---------------------------
# Account Deactivation
# ---------------------------
class AccountDeactivateSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = self.context['request'].user
        if not user.check_password(attrs['password']):
            raise serializers.ValidationError({"password": "Incorrect password."})
        attrs['user'] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data['user']
        user.is_active = False
        user.is_permanent_disabled = True
        user.updated_at = timezone.now()
        user.save(update_fields=["is_active", "is_permanent_disabled", "updated_at"])
    
        html_message = render_to_string("emails/account_deactive.html", {
            "first_name": user.first_name,  
            "app_name": "Note AI"
        })

    
        plain_message = strip_tags(html_message)
        

        send_mail(
            subject="Account Deactivated – Scheduled for Deletion",
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
        )

        store_activity(self.context["request"],"Account deactivated", self.user, {}, 200, True, "")
        return user


# ---------------------------
# Account Restore
# ---------------------------
class AccountRestoreSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = normalize_email(attrs['email'])
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User not found."})

        if not user.check_password(attrs['password']):
            raise serializers.ValidationError({"password": "Incorrect password."})

        if user.is_active:
            raise serializers.ValidationError({"email": "Account is already active."})

        attrs['user'] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data['user']
        user.is_active = True
        user.is_permanent_disabled = False
        user.updated_at = timezone.now()
        user.save(update_fields=["is_active", "is_permanent_disabled", "updated_at"])


        html_message = render_to_string("emails/account_restore.html", {
            "first_name": user.first_name,  
            "app_name": "Note AI"
        })

    
        plain_message = strip_tags(html_message)
        

        send_mail(
            subject="Account Restored",
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
        )

        store_activity(self.context["request"],"Account restored", self.user, {}, 200, True, "")
        return user


# ---------------------------
# Public User & Follow
# ---------------------------
class UserPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "first_name", "last_name"]
        
class FollowSerializer(serializers.ModelSerializer):
    follower = UserPublicSerializer(read_only=True)
    following = UserPublicSerializer(read_only=True)

    class Meta:
        model = Follow
        fields = ["id", "follower", "following", "created_at"]


# ---------------------------
# Hybrid Token Refresh
# ---------------------------
class TokenRefreshSerializer(serializers.Serializer):
    """
    Hybrid-friendly:
    - If `refresh` is provided in the request body -> use it (mobile).
    - Otherwise, look for `refresh_token` cookie via self.context['request'] (web).
    Respects SIMPLE_JWT.ROTATE_REFRESH_TOKENS.
    """
    refresh = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        request = self.context.get("request")
        supplied = (attrs.get("refresh") or "").strip()

        refresh_raw = supplied
        if not refresh_raw and request is not None:
            refresh_raw = request.COOKIES.get("refresh_token", "")

        if not refresh_raw:
            raise serializers.ValidationError({"refresh": "No refresh token provided."})

        try:
            refresh_obj = RefreshToken(refresh_raw)
            access_token = str(refresh_obj.access_token)

            # Respect rotation setting
            rotate = bool(getattr(settings, "SIMPLE_JWT", {}).get("ROTATE_REFRESH_TOKENS", False))
            if rotate:
                # When rotating, new refresh is the same object stringified after access usage
                new_refresh = str(refresh_obj)
                return {"access": access_token, "refresh": new_refresh}

            # No rotation: do not leak refresh unnecessarily
            return {"access": access_token}

        except Exception:
            raise serializers.ValidationError({"refresh": "Invalid or expired refresh token."})



class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['tokens','updated_at']  # Or specify only the fields you want to expose


class UserActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserActivity
        fields = [ 
            'activity_type', 
            'ip_address',
            'geo_country', 
            'geo_city', 
            'user_agent', 
            'browser',
            'browser_version',
            'os', 
            'os_version',
            'device_type', 
            'device_brand',
            'device_model', 
            'action_date_time',
            'is_successful',
        ] # Or specify only the fields you want to expose


class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = ['transaction_type','tokens','description','created_at']  # Or specify only the fields you want to expose




class UserPublicProfileSerializer(serializers.ModelSerializer):
    followers_count = serializers.IntegerField(read_only=True)
    following_count = serializers.IntegerField(read_only=True)
    notes_count = serializers.IntegerField(read_only=True)  # ✅ added

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "first_name",
            "last_name",
            "profile_picture",
            "followers_count",
            "following_count",
            "notes_count",   # ✅ make sure this is included
        ]