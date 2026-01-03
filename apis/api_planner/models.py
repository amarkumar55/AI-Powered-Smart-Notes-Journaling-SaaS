from django.db import models
from django.utils import timezone
from datetime import datetime, timedelta
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from apis.api_auth.models import TimeStampMixin

User = get_user_model()


class PlannerEntry(TimeStampMixin):
    
    STATUS_PLANNED = "planned"
    STATUS_DONE = "done"
    STATUS_SKIPPED = "skipped"
    STATUS_CHOICES = [
        (STATUS_PLANNED, "Planned"),
        (STATUS_DONE, "Done"),
        (STATUS_SKIPPED, "Skipped"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="planner_entries",
    )

    # When does this happen?
    date = models.DateField()

    # Optional time window (omit for all-day)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    is_all_day = models.BooleanField(default=False)

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    location = models.CharField(max_length=200, blank=True)

    # Reminders / notifications
    reminder_minutes_before = models.PositiveIntegerField(null=True, blank=True)
    want_notification = models.BooleanField(default=False)
    reminder_datetime = models.DateTimeField(null=True, blank=True, db_index=True)  # 🔥 denormalized

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PLANNED)
    class Meta:
        ordering = ["date", "start_time", "id"]
        indexes = [
            models.Index(fields=["user", "date"]),
            models.Index(fields=["status", "date"]),  # optional extra for queries
        ]

    def __str__(self):
        return f"{self.title} @ {self.date} ({self.user_id})"

    # 🔒 Validation
    def clean(self):
        if self.start_time and self.end_time and self.start_time >= self.end_time:
            raise ValidationError("End time must be after start time.")

    # Compute reminder datetime
    def compute_reminder_datetime(self):
        if not self.want_notification or self.reminder_minutes_before is None:
            return None
        if self.is_all_day or not self.start_time:
            event_dt = datetime.combine(
                self.date,
                datetime.min.time(),
                tzinfo=timezone.get_current_timezone(),
            )
        else:
            event_dt = timezone.make_aware(datetime.combine(self.date, self.start_time))
        return event_dt - timedelta(minutes=self.reminder_minutes_before)

    # Override save to keep reminder_datetime denormalized
    def save(self, *args, **kwargs):
        self.reminder_datetime = self.compute_reminder_datetime()
        super().save(*args, **kwargs)
