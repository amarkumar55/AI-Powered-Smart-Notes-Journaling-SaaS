import uuid
import bleach
import hashlib
from datetime import timedelta
from django.db.models import F
from django.utils import timezone
from django.core.cache import cache
from django.db import models, transaction
from django.db.models.functions import Lower
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector
from encrypted_model_fields.fields import EncryptedIntegerField
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from .utlity import ( COOLDOWN_MINUTES, MAX_ATTEMPTS, EXPIRY_MINUTES )

from django.apps import apps

def get_plan_purchase_model():
    return apps.get_model('api_subscription', 'PlanPurchase')


class TimeStampMixin(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# -------------------------------
# User Manager
# -------------------------------
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        if not password:
            raise ValueError('The Password field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_admin', True)
        return self.create_user(email, password, **extra_fields)

    def create_admin(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_staff', False)
        return self.create_user(email, password, **extra_fields)

    def create_staff(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_admin', False)
        extra_fields.setdefault('is_staff', True)
        return self.create_user(email, password, **extra_fields)

# -------------------------------
# User Model
# -------------------------------
def validate_profile_image(file):
    max_size_mb = 1
    if file.size > max_size_mb * 1024 * 1024:
        raise ValidationError(f"Max file size is {max_size_mb}MB")
    valid_types = ["image/jpeg", "image/jpg", "image/png", "image/gif"]
    if file.content_type not in valid_types:
        raise ValidationError("Unsupported file type")
    

class CustomUser(AbstractBaseUser, PermissionsMixin, TimeStampMixin):
    alphabetic = RegexValidator(regex=r'^[a-zA-Z]*$', message='Field must contain only alphabetic characters.')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Required fields
    first_name = models.CharField(max_length=30, validators=[alphabetic])
    last_name = models.CharField(max_length=30, validators=[alphabetic])
    email = models.EmailField(unique=True, error_messages={'unique':'A user with this email already exists.'})
    is_email_verified = models.BooleanField(default=False)
    username = models.CharField(max_length=30, unique=True)
    birth_date = models.DateField()
    gender = models.CharField(max_length=10, choices=[("Male","Male"),("Female","Female"),("Other","Other")])
    date_joined = models.DateTimeField(auto_now_add=True)

    # Permissions
    is_superuser = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_user = models.BooleanField(default=True)
    is_accepted_terms = models.BooleanField(default=False)

    # Optional fields
    country_code = models.CharField(max_length=3, blank=True, null=True)
    state_code = models.CharField(max_length=10, blank=True, null=True)
    city = models.CharField(max_length=50, blank=True, null=True)
    cell = models.CharField(max_length=12, blank=True, null=True)
    is_cell_verified = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to='uploads/profiles/', blank=True, null=True,
                                        validators=[validate_profile_image])
    language_preference = models.CharField(max_length=10, default="en")
    notification_preference = models.BooleanField(default=True)
    bio = models.TextField(blank=True, null=True)
    
    is_permanent_disabled = models.BooleanField(default=False, blank=True, null=True)
    is_remember_me = models.BooleanField(default=False, blank=True, null=True)
    password_reset_token = models.TextField(blank=True, null=True)
    password_reset_expires_at = models.DateTimeField(blank=True, null=True)
    two_factor_enabled = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    followers_count = models.PositiveIntegerField(default=0)
    following_count = models.PositiveIntegerField(default=0)

    objects = CustomUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'birth_date', 'gender', 'username']

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        constraints = [
            models.UniqueConstraint(Lower("email"), name="uniq_user_email_ci"),
            models.UniqueConstraint(Lower("username"), name="uniq_user_username_ci"),
        ]
        indexes = [
            models.Index(fields=["email"], name="idx_user_email"),
            models.Index(fields=["first_name", "last_name"], name="idx_user_name"),
            GinIndex(
                SearchVector("first_name", "last_name", config="simple"),
                name="idx_user_fts_name"
            )
        ]

    def save(self, *args, **kwargs):
        self.first_name = bleach.clean(self.first_name, tags=[], strip=True)
        self.last_name = bleach.clean(self.last_name, tags=[], strip=True)
        self.email = bleach.clean(self.email, tags=[], strip=True)
        self.gender = bleach.clean(self.gender, tags=[], strip=True)
        super().save(*args, **kwargs)


    def set_password_reset_token(self, token: str, expiry_minutes: int = 5):
        """
        Securely set a hashed password reset token with expiry.
        """
        self.password_reset_token = make_password(token)  # hash token
        self.password_reset_expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
        self.save(update_fields=["password_reset_token", "password_reset_expires_at"])

    def verify_password_reset_token(self, token: str) -> bool:
        """
        Verify provided token against hashed DB token and expiry.
        """
        if not self.password_reset_token or not self.password_reset_expires_at:
            return False
        if timezone.now() > self.password_reset_expires_at:
            return False
        return check_password(token, self.password_reset_token)

    def clear_password_reset_token(self):
        """
        Clear token after successful reset or expiry.
        """
        self.password_reset_token = None
        self.password_reset_expires_at = None
        self.save(update_fields=["password_reset_token", "password_reset_expires_at"])


User = get_user_model()

# -------------------------------
# User Activity Model
# -------------------------------
class UserActivity(TimeStampMixin):
    user = models.ForeignKey(User, related_name="activities", on_delete=models.SET_NULL, null=True, blank=True)
    session_id = models.CharField(max_length=255, null=True, blank=True)
    activity_type = models.CharField(max_length=100)
    endpoint = models.CharField(max_length=255, null=True, blank=True)
    method = models.CharField(max_length=10, null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    data = models.JSONField(default=dict, blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    geo_country = models.CharField(max_length=100, null=True, blank=True)
    geo_city = models.CharField(max_length=100, null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    browser = models.CharField(max_length=100, null=True, blank=True)
    browser_version = models.CharField(max_length=100, null=True, blank=True)
    os = models.CharField(max_length=100, null=True, blank=True)
    os_version = models.CharField(max_length=100, null=True, blank=True)
    device_type = models.CharField(max_length=50, null=True, blank=True)
    device_brand = models.CharField(max_length=100, null=True, blank=True)
    device_model = models.CharField(max_length=100, null=True, blank=True)
    is_successful = models.BooleanField(default=True)
    error_message = models.TextField(blank=True, null=True)
    action_date_time = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = "User Activity"
        verbose_name_plural = "User Activities"
        ordering = ["-action_date_time"]
        indexes = [
            models.Index(fields=["user", "action_date_time"], name="idx_activity_user_date"),
            models.Index(fields=["activity_type"], name="idx_activity_type"),
            models.Index(fields=["user", "activity_type", "action_date_time"], name="idx_user_activity_type_date"),
            GinIndex(
                SearchVector("activity_type", config="simple"),
                name="idx_activity_fts_type",
            ),
        ]

    def set_session(self, raw_session_id):
        """Hash session_id before storing."""
        if raw_session_id:
            self.session_id = hashlib.sha256(raw_session_id.encode()).hexdigest()


    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Invalidate cache for this user after saving new activity
        cache_key = f"user_activity_recent:{self.user_id}"
        cache.delete(cache_key)

    @classmethod
    def recent_for_user(cls, user_id, limit=50):
        """
        Return the most recent activities for a user with caching.
        """
        cache_key = f"user_activity_recent:{user_id}"
        activities = cache.get(cache_key)
        if activities is None:
            activities = list(cls.objects.filter(user_id=user_id)
                              .order_by("-action_date_time")[:limit])
            cache.set(cache_key, activities, 300)  # cache 5 minutes
        return activities
    
    
# -------------------------------
# Email OTP Model
# -------------------------------

def default_expiry():
    return timezone.now() + timedelta(minutes=EXPIRY_MINUTES)

class EmailOTP(TimeStampMixin):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=128)
    failed_attempts = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True, default=default_expiry)

    # -------------------------------
    # Helpers
    # -------------------------------
    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at

    def _attempts_cache_key(self):
        return f"otp_attempts:{self.email}:{int(self.created_at.timestamp())}"

    def _cooldown_cache_key(self):
        return f"otp_cooldown:{self.email}"

    def attempts(self) -> int:
        return cache.get(self._attempts_cache_key(), 0)

    def is_in_cooldown(self) -> bool:
        return cache.get(self._cooldown_cache_key(), False)

    # -------------------------------
    # OTP Management
    # -------------------------------
    def can_request_new_otp(self) -> bool:
        """Check if user is allowed to request a new OTP."""
        if self.is_in_cooldown():
            return False
        if not self.is_expired():
            return False  # still valid OTP
        return True

    def set_otp(self, otp: str, request_ip: str = None):
        """Issue new OTP if allowed."""
    
        self.otp = make_password(str(otp))
        now = timezone.now()
        self.created_at = now
        self.expires_at = now + timedelta(minutes=EXPIRY_MINUTES)
        self.failed_attempts = 0
        self.save(update_fields=["otp", "created_at", "expires_at", "failed_attempts"])

        # Reset counters
        cache.delete(self._attempts_cache_key())
        cache.delete(self._cooldown_cache_key())

    def verify_otp(self, otp_input: str, request_ip: str = None) -> bool:
        """Check OTP validity."""
        if self.is_in_cooldown():
            return False

        if self.is_expired():
            return False

        attempts = self.attempts()

        if attempts >= MAX_ATTEMPTS:
            cache.set(self._cooldown_cache_key(), True, timeout=60 * COOLDOWN_MINUTES)
            return False

        if check_password(str(otp_input), self.otp):
            cache.delete(self._attempts_cache_key())  # reset attempts
            return True

        # failed attempt
        cache.incr(self._attempts_cache_key(), delta=1)
        remaining_seconds = int((self.expires_at - timezone.now()).total_seconds())
        cache.expire(self._attempts_cache_key(), max(remaining_seconds, 60))

        self.failed_attempts += 1
        self.save(update_fields=["failed_attempts"])

        if cache.get(self._attempts_cache_key(), 0) >= MAX_ATTEMPTS:
            cache.set(self._cooldown_cache_key(), True, timeout=60 * COOLDOWN_MINUTES)

        return False

    class Meta:
        indexes = [
            models.Index(fields=["email"], name="idx_otp_email"),
            models.Index(fields=["expires_at"], name="idx_otp_expires"),
            models.Index(fields=["created_at"], name="idx_otp_created"),
        ]
        

# -------------------------------
# Wallet Model
# -------------------------------
class Wallet(TimeStampMixin):
    

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField('CustomUser', on_delete=models.CASCADE, related_name='wallet')
    tokens = EncryptedIntegerField(default=0)

    class Meta:
        verbose_name = 'Wallet'
        verbose_name_plural = 'Wallets'
        indexes = [models.Index(fields=["user"], name="idx_user")]

    def clean(self):
        if self.tokens <= 0:
            raise ValidationError("Tokens must be positive")
        
    @transaction.atomic
    def credit_from_register(self, tokens):

        wallet = Wallet.objects.select_for_update().get(pk=self.pk)
        wallet.tokens = tokens
        wallet.save(update_fields=["tokens"])
        wallet.refresh_from_db()
        self.transactions.create(tokens=tokens, transaction_type="credit", description=f"Signup Bonus")

    @transaction.atomic
    def credit_from_purchase(self, purchase):

        if not purchase.is_successful:
            raise ValidationError("Purchase not confirmed.")
        
        if self.transactions.filter(purchase=purchase).exists():
            raise ValidationError("Purchase already credited.")
        
        wallet = Wallet.objects.select_for_update().get(pk=self.pk)
        wallet.tokens = int(wallet.tokens) + int(purchase.plan.tokens)
        wallet.save(update_fields=["tokens"])
        wallet.refresh_from_db()
        self.transactions.create(tokens=purchase.plan.tokens, transaction_type="credit",
                                 description=f"Credited via {purchase.plan.name}", purchase=purchase)

    @transaction.atomic
    def debit_tokens(self, tokens: int, description=""):
        if tokens <= 0:
            raise ValidationError("Debit must be positive.")
        
        wallet = Wallet.objects.select_for_update().get(pk=self.pk)

        if wallet.tokens < tokens:
            raise ValidationError("Insufficient tokens.")
        
        wallet.tokens = int(wallet.tokens) - int(tokens)
        wallet.save(update_fields=["tokens"])
        wallet.refresh_from_db()
        self.transactions.create(tokens=tokens, transaction_type="debit", description=description or "Tokens spent")


class WalletTransactionManager(models.Manager):
    def recent(self, wallet_id, days=30):
        """
        Get recent transactions with caching.
        """
        cache_key = f"wallet_txn_recent:{wallet_id}"
        txns = cache.get(cache_key)
        if txns is None:
            since = timezone.now() - timedelta(days=days)
            txns = list(self.filter(wallet_id=wallet_id, created_at__gte=since)
                        .order_by("-created_at"))
            cache.set(cache_key, txns, 300)  # cache 5 minutes
        return txns

    def total_tokens(self, wallet_id, txn_type=None):
        """
        Total tokens (credit/debit) with optional caching.
        """
        cache_key = f"wallet_total:{wallet_id}:{txn_type or 'all'}"
        total = cache.get(cache_key)
        if total is None:
            qs = self.filter(wallet_id=wallet_id)
            if txn_type:
                qs = qs.filter(transaction_type=txn_type)
            total = qs.aggregate(total=models.Sum("tokens"))["total"] or 0
            cache.set(cache_key, total, 300)  # cache 5 minutes
        return total
    
# -------------------------------
# Wallet Transaction Model
# -------------------------------
class WalletTransaction(TimeStampMixin):

    TRANSACTION_TYPES = [('credit','Credit'), ('debit','Debit')]
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    tokens = EncryptedIntegerField()
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    description = models.CharField(max_length=255, blank=True, null=True)
    purchase = models.ForeignKey('api_subscription.PlanPurchase', null=True, blank=True, on_delete=models.SET_NULL)
    objects = WalletTransactionManager()
    class Meta:
        verbose_name = 'Wallet Transaction'
        verbose_name_plural = 'Wallet Transactions'
        ordering = ['-created_at']
    
        indexes = [
            models.Index(fields=["wallet", "created_at"], name="idx_txn_wallet_date"),
            models.Index(fields=["transaction_type", "created_at"], name="idx_txn_type_date"),
            models.Index(fields=["wallet", "transaction_type", "created_at"], name="idx_wallet_type_date"),
        ] 
        

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Invalidate caches related to this wallet
        cache.delete(f"wallet_txn_recent:{self.wallet_id}")
        cache.delete(f"wallet_total:{self.wallet_id}:all")
        cache.delete(f"wallet_total:{self.wallet_id}:{self.transaction_type}")
    
    def clean(self):
        if self.tokens <= 0:
            raise ValidationError("Tokens must be positive")
        
# -------------------------------
# Follow Model
# -------------------------------
class Follow(TimeStampMixin):
    follower = models.ForeignKey(User, related_name="following", on_delete=models.CASCADE)
    following = models.ForeignKey(User, related_name="followers", on_delete=models.CASCADE)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['follower', 'following'], name='unique_follow'),
        ]
        verbose_name = 'User Followers & following list'
        verbose_name_plural = 'User Followers & following list'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=["follower"], name="idx_follow_follower"),
            models.Index(fields=["following"], name="idx_follow_following"),
            models.Index(fields=("follower", "following"),  name="idx_follow_pair"),
            models.Index(fields=("following", "follower"),  name="idx_follow_reverse"),
        ]


