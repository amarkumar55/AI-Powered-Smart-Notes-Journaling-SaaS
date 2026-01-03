from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from apis.api_auth.models import TimeStampMixin

User = get_user_model()


class Notification(TimeStampMixin):
    """Model for user notifications with optimized indexing & safety."""

    NOTIFICATION_TYPES = [
        ('system', 'System'),
        ('app', 'App'),
        ('email', 'Email'),
        ('promotion', 'Promotion'),
    ]

    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name="notifications",
        db_index=True
    )
    notification_type = models.CharField(
        max_length=20, 
        choices=NOTIFICATION_TYPES, 
        db_index=True
    )
    title = models.CharField(max_length=200, db_index=True)  
    message = models.TextField()
    is_read = models.BooleanField(default=False, db_index=True)
    read_at = models.DateTimeField(blank=True, null=True, db_index=True)
    data = models.JSONField(default=dict, blank=True)  # flexible extra payload

    class Meta:
        verbose_name = "Notification"
        verbose_name_plural = "Notifications"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "is_read"]),   # Fast unread lookups
            models.Index(fields=["notification_type"]), # Filter by type quickly
            models.Index(fields=["created_at"]),        # Recent notifications
        ]

    def __str__(self):
        return f"Notification({self.user.username}, {self.title})"

    def mark_as_read(self):
        """Mark the notification as read safely."""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=["is_read", "read_at", "updated_at"])
