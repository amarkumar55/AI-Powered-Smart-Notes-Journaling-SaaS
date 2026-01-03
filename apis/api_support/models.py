import bleach
from django.db import models
from django.core.validators import RegexValidator
from apis.api_auth.models import TimeStampMixin

class ContactQuery(TimeStampMixin):
    alphabetic = RegexValidator(
        regex=r'^[a-zA-Z ]*$',  # Allows spaces in names
        message='Field must contain only alphabetic characters and spaces.'
    )

    full_name = models.CharField(
        max_length=30,
        blank=False,
        null=False,
        validators=[alphabetic],
        verbose_name="Full Name"
    )

    email = models.EmailField(
        blank=False,
        null=False,
        verbose_name="Email Address"
    )

    message = models.TextField(
        blank=False,
        null=False,
        verbose_name="Message"
    )

    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def save(self, *args, **kwargs):
        # sanitize only name + message (email is already validated by EmailField)
        self.full_name = bleach.clean(self.full_name, tags=[], strip=True)
        self.message = bleach.clean(self.message, tags=[], strip=True)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.full_name} - {self.email}"

    class Meta:
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["-created_at"]),
        ]


class SystemMetrics(TimeStampMixin):
    timestamp = models.DateTimeField(auto_now_add=True)
    cpu_usage = models.FloatField(default=0)
    memory_usage = models.FloatField(default=0)
    api_calls = models.IntegerField(default=0)
    error_count = models.IntegerField(default=0)

    class Meta:
        verbose_name = 'System Metric'
        verbose_name_plural = 'System Metrics'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=["timestamp"]),
        ]


class SiteSettings(TimeStampMixin):
    site_name = models.CharField(max_length=255)
    site_description = models.TextField(blank=True)
    contact_email = models.EmailField()
    contact_phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    social_facebook = models.URLField(blank=True)
    social_twitter = models.URLField(blank=True)
    social_instagram = models.URLField(blank=True)
    social_youtube = models.URLField(blank=True)
    maintenance_mode = models.BooleanField(default=False)

    def __str__(self):
        return self.site_name

    class Meta:
        # enforce only one settings row
        constraints = [
            models.UniqueConstraint(fields=["id"], name="unique_site_settings_singleton")
        ]


class AppLog(TimeStampMixin):
    LEVEL_CHOICES = [
        ('ERROR', 'Error'),
        ('WARNING', 'Warning'),
        ('INFO', 'Info'),
        ('DEBUG', 'Debug'),
    ]

    level = models.CharField(max_length=10, choices=LEVEL_CHOICES)
    message = models.TextField()
    traceback = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # truncate overly large logs to prevent DB bloat
        if self.message and len(self.message) > 2000:
            self.message = self.message[:2000] + "..."
        if self.traceback and len(self.traceback) > 5000:
            self.traceback = self.traceback[:5000] + "..."
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.level} @ {self.timestamp}: {self.message[:50]}"

    class Meta:
        indexes = [
            models.Index(fields=["level"]),
            models.Index(fields=["timestamp"]),
        ]
