# plans/models.py
import json
import uuid
from django.db import models
from django.utils.text import slugify
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from apis.api_auth.models import TimeStampMixin
from encrypted_model_fields.fields import  EncryptedTextField

User = get_user_model()

class Plan(TimeStampMixin):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)
    slug = models.SlugField(unique=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    tokens = models.PositiveIntegerField(
        help_text="Number of days (or credits) the plan is valid"
    )
    razorpay_plan_id = models.CharField(max_length=200, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["is_active", "price"])]

    def clean(self):
        if self.price < 0:
            raise ValidationError("Plan price cannot be negative.")
        if self.tokens <= 0:
            raise ValidationError("Tokens must be greater than zero.")

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name).lower()
            slug = base_slug
            counter = 1
            while Plan.objects.filter(slug=slug).exclude(id=self.id).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name} ({self.price} {self.tokens} tokens)"


class PlanPurchase(TimeStampMixin):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="purchases")
    plan = models.ForeignKey(Plan, on_delete=models.CASCADE, related_name="purchases")
    payment_id = models.CharField(max_length=255, unique=True)  # Razorpay ID
    order_id = models.CharField(max_length=255, db_index=True)  # Razorpay order_id
    is_successful = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "plan", "payment_id"],
                name="unique_user_plan_payment",
            )
        ]

    def __str__(self):
        return f"{self.user} - {self.plan.name} ({'✅' if self.is_successful else '❌'})"


class UserTransaction(TimeStampMixin):
    PAYMENT_METHOD_CHOICES = [
        ("Credit Card", "Credit Card"),
        ("Debit Card", "Debit Card"),
        ("UPI", "UPI"),
        ("PayPal", "PayPal"),
        ("Net Banking", "Net Banking"),
        ("Wallet", "Wallet"),
    ]

    STATUS_CHOICES = [
        ("Pending", "Pending"),
        ("Success", "Success"),
        ("Failed", "Failed"),
        ("Refunded", "Refunded"),
        ("Cancelled", "Cancelled"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey( User, on_delete=models.CASCADE, related_name="transactions")
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    transaction_id = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default="INR")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    encrypted_gateway_response = EncryptedTextField(blank=True, null=True)
    refund_id = models.CharField(max_length=255, blank=True, null=True)
    refunded_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    transaction_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-transaction_date"]
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["transaction_id"]),
            models.Index(fields=["status", "transaction_date"]),
        ]
        
    def clean(self):
        if self.amount > 500:
            raise ValidationError("amount must be less then 500")
    

    def set_gateway_response(self, response: dict):
        # Only keep safe keys
        allowed_keys = {"transaction_id", "order_id", "status", "amount", "currency", "payment_method", "gateway_ref"}
        safe_response = {k: v for k, v in response.items() if k in allowed_keys}
        self.encrypted_gateway_response = json.dumps(safe_response)
    
    def get_gateway_response(self) -> dict:
        try:
            return json.loads(self.encrypted_gateway_response) if self.encrypted_gateway_response else {}
        except Exception:
            return {}



