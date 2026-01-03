# payments/models.py
import json
import uuid
import hashlib
from decimal import Decimal
from django.db import models, transaction
from django.contrib.auth import get_user_model
from apis.api_auth.models import TimeStampMixin
from django.core.exceptions import ValidationError
from encrypted_model_fields.fields import EncryptedTextField

User = get_user_model()
# ----------------------------
# Validators
# ----------------------------
def validate_positive_amount(value):
    if value is None:
        raise ValidationError("Amount cannot be null.")
    try:
        dec = Decimal(value)
    except Exception:
        raise ValidationError("Invalid decimal value.")
    if dec <= 0:
        raise ValidationError("Amount must be positive.")


# ----------------------------
# Managers
# ----------------------------
class PaymentManager(models.Manager):
    def for_user(self, user):
        return self.get_queryset().filter(user=user)


class PaymentAuditLogManager(models.Manager):
    def recent_for_payment(self, payment_id, limit=50):
        return self.get_queryset().filter(payment_id=payment_id).order_by("-created_at")[:limit]


# ----------------------------
# Core Models
# ----------------------------
class Payment(TimeStampMixin):
    
    STATUS_PENDING = "pending"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_REFUNDED = "refunded"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
        (STATUS_REFUNDED, "Refunded"),
    ]

    METHOD_CHOICES = [
        ("razorpay", "Razorpay"),
        ("stripe", "Stripe"),
        ("paypal", "PayPal"),
        ("wallet", "Wallet"),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="payment_records")
    amount = models.DecimalField(max_digits=12, decimal_places=2, validators=[validate_positive_amount])
    currency = models.CharField(max_length=8, default="INR")
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=STATUS_PENDING)
    payment_method = models.CharField(max_length=20, choices=METHOD_CHOICES)
    payment_id = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    order_id = models.CharField(max_length=128, blank=True, null=True)
    description = EncryptedTextField(blank=True, null=True)
    gateway_status = models.CharField(max_length=64, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "created_at"], name="idx_payment_user_date"),
            models.Index(fields=["payment_id"], name="idx_payment_payment_id"),
        ]
        ordering = ["-created_at"]

    def mark_success(self, payment_id: str = None, gateway_status: str = None):
        with transaction.atomic():
            if payment_id:
                self.payment_id = payment_id
            if gateway_status:
                self.gateway_status = gateway_status
            self.status = self.STATUS_SUCCESS
            self.save(update_fields=["payment_id", "gateway_status", "status", "updated_at"])


class Refund(TimeStampMixin):
    STATUS_PENDING = "pending"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name="refunds")
    amount = models.DecimalField(max_digits=12, decimal_places=2, validators=[validate_positive_amount])
    currency = models.CharField(max_length=8, default="INR")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    refund_id = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    reason = EncryptedTextField(blank=True, null=True)


    class Meta:
        indexes = [
            models.Index(fields=["refund_id"], name="idx_refund_refund_id"),
            models.Index(fields=["payment", "created_at"], name="idx_refund_payment_date"),
        ]
        ordering = ["-created_at"]


# ----------------------------
# Audit Logging (Tamper-evident)
# ----------------------------
class PaymentAuditLog(TimeStampMixin):
    ACTION_PAYMENT_CREATE = "payment_create"
    ACTION_CAPTURE = "payment_capture"
    ACTION_REFUND_REQUEST = "refund_request"
    ACTION_REFUND_EXECUTE = "refund_execute"
    ACTION_CHOICES = [
        (ACTION_PAYMENT_CREATE, "Payment Create"),
        (ACTION_CAPTURE, "Payment Capture"),
        (ACTION_REFUND_REQUEST, "Refund Request"),
        (ACTION_REFUND_EXECUTE, "Refund Execute"),
    ]

    OUTCOME_SUCCESS = "success"
    OUTCOME_FAILURE = "failure"
    OUTCOME_CHOICES = [
        (OUTCOME_SUCCESS, "Success"),
        (OUTCOME_FAILURE, "Failure"),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)
    outcome = models.CharField(max_length=10, choices=OUTCOME_CHOICES)
    message = models.TextField(blank=True, default="")

    # 🔒 Privacy: store hashed IP and User-Agent for forensic uniqueness, not raw PII
    ip_address_hash = models.CharField(max_length=128, blank=True, null=True)
    user_agent_hash = models.CharField(max_length=128, blank=True, null=True)

    request_id_hash = models.CharField(max_length=128, blank=True, db_index=True)
    payment_id = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    refund_id = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=8, blank=True, default="")

    prev_hash = models.CharField(max_length=128, blank=True, null=True)
    entry_hash = models.CharField(max_length=128, unique=True, db_index=True)

    objects = PaymentAuditLogManager()

    class Meta:
        ordering = ["-created_at"]

    def _serialize_for_hash(self):
        data = {
            "user_id": self.user_id,
            "action": self.action,
            "outcome": self.outcome,
            "message": self.message,
            "ip_address_hash": self.ip_address_hash,
            "user_agent_hash": self.user_agent_hash,
            "request_id_hash": self.request_id_hash,
            "payment_id": self.payment_id,
            "refund_id": self.refund_id,
            "amount": str(self.amount) if self.amount else None,
            "currency": self.currency,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "prev_hash": self.prev_hash,
        }
        return json.dumps(data, sort_keys=True)

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("Audit logs are immutable — cannot update existing entry.")

        # Hash PII before saving
        if self.ip_address_hash and not self.ip_address_hash.startswith("sha256:"):
            self.ip_address_hash = "sha256:" + hashlib.sha256(self.ip_address_hash.encode()).hexdigest()
        if self.user_agent_hash and not self.user_agent_hash.startswith("sha256:"):
            self.user_agent_hash = "sha256:" + hashlib.sha256(self.user_agent_hash.encode()).hexdigest()

        last = PaymentAuditLog.objects.order_by("-created_at").first()
        self.prev_hash = last.entry_hash if last else None
        raw_string = self._serialize_for_hash()
        self.entry_hash = hashlib.sha256(raw_string.encode()).hexdigest()

        super().save(*args, **kwargs)

    @classmethod
    def verify_chain(cls, limit=None):
        qs = cls.objects.order_by("created_at")
        if limit:
            qs = qs[:limit]

        prev_hash = None
        for entry in qs:
            expected = entry.prev_hash
            if expected != prev_hash:
                return False
            recalculated = hashlib.sha256(entry._serialize_for_hash().encode()).hexdigest()
            if recalculated != entry.entry_hash:
                return False
            prev_hash = entry.entry_hash
        return True


class AuditChainCheck(TimeStampMixin):
    STATUS_OK = "ok"
    STATUS_BROKEN = "broken"
    STATUS_ERROR = "error"
    STATUS_CHOICES = [
        (STATUS_OK, "OK (Intact)"),
        (STATUS_BROKEN, "Broken (Tampering Detected)"),
        (STATUS_ERROR, "Error During Verification"),
    ]

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, db_index=True)
    checked_at = models.DateTimeField(auto_now_add=True, db_index=True)
    checked_by = models.CharField(max_length=64, blank=True, default="system")
    details = models.TextField(blank=True, default="")
    last_verified_log_id = models.BigIntegerField(null=True, blank=True)

    class Meta:
        ordering = ["-checked_at"]
        indexes = [
            models.Index(fields=["status", "checked_at"], name="idx_chaincheck_status_date"),
        ]


    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValueError("AuditChainCheck entries are immutable and cannot be modified once created.")
        super().save(*args, **kwargs)
