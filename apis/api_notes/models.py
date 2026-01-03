import os
import uuid
import bleach
from PIL import Image
from django.db import models
from django.db.models import F
from django.utils.text import slugify
from django.contrib.auth import get_user_model
from apis.api_auth.models import TimeStampMixin
from django.core.exceptions import ValidationError
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField


User = get_user_model()

# ---------- Helpers ----------

def _uuid_filename(instance, filename):
    ext = os.path.splitext(filename)[1].lower()
    return f"notes/images/{uuid.uuid4().hex}{ext}"


def validate_note_image(file):
    # Validate size
    max_size_mb = 1
    if hasattr(file, "size") and file.size > max_size_mb * 1024 * 1024:
        raise ValidationError(f"Max file size is {max_size_mb}MB")

    # Validate image actually opens (safer than trusting content_type)
    try:
        file.open()
        Image.open(file).verify()
        file.close()
    except Exception:
        raise ValidationError("Invalid or corrupted image file")


# ---------- Tag & through model (indexed) ----------
class Tag(TimeStampMixin):
    name = models.CharField(max_length=50, unique=True, db_index=True)


class NoteTag(models.Model):
    note = models.ForeignKey("Note", on_delete=models.CASCADE, related_name="note_tags")
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name="tagged_notes")

    class Meta:
        unique_together = ("note", "tag")
        indexes = [models.Index(fields=["tag"]), models.Index(fields=["note"])]
        constraints = [
           models.UniqueConstraint(fields=["note", "tag"], name="unique_note_tag")
        ]


# ---------- Note model ----------
class Note(TimeStampMixin):

    NOTE_TYPE_CHOICES = [
        ("text", "Text"),
        ("live_audio", "Live Audio"),
        ("uploaded_audio", "Uploaded Audio"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notes", db_index=True)
    title = models.CharField(max_length=255)
    # slug is secure (uuid suffix) to avoid guessable predictable slugs for private notes
    slug = models.SlugField(unique=True, max_length=255)
    content = models.TextField(blank=True)
    tags = models.ManyToManyField(Tag, related_name="notes", blank=True, through=NoteTag)
    is_public = models.BooleanField(default=False, db_index=True)
    type = models.CharField(max_length=20, choices=NOTE_TYPE_CHOICES, default="text", db_index=True)
    search_vector = SearchVectorField(null=True, editable=False)
    is_publish = models.BooleanField(default=True)
    # Denormalized counters for fast read
    views_count = models.PositiveIntegerField(default=0)
    likes_count = models.PositiveIntegerField(default=0)
    comments_count = models.PositiveIntegerField(default=0)
    shares_count = models.PositiveIntegerField(default=0)
    trending_score = models.IntegerField(default=0, db_index=True)
    
    class Meta:
        indexes = [
            models.Index(fields=["is_public"]),
            models.Index(fields=["type"]),
            models.Index(fields=["user", "created_at"]),
            GinIndex(fields=["search_vector"]),
        ]

    def save(self, *args, **kwargs):
        # ensure secure slug when creating
        if not self.slug:
            base = slugify(self.title)[:80] or "note"
            for _ in range(5):  # max 5 retries
                slug = f"{base}-{uuid.uuid4().hex[:10]}"
                if not Note.objects.filter(slug=slug).exists():
                    self.slug = slug
                    break
        super().save(*args, **kwargs)

    # Atomic helpers
    def increment_views(self, by: int = 1):
        Note.objects.filter(pk=self.pk).update(views_count=F("views_count") + by)

    def inc_likes(self):
        Note.objects.filter(pk=self.pk).update(likes_count=F("likes_count") + 1)

    def dec_likes(self):
        Note.objects.filter(pk=self.pk).update(likes_count=F("likes_count") - 1)


# ---------- NoteImage ----------
class NoteImage(TimeStampMixin):
    note = models.ForeignKey("Note", on_delete=models.CASCADE, related_name="images")
    image = models.ImageField(upload_to=_uuid_filename, validators=[validate_note_image])

# ---------- NoteLike ----------
class NoteLike(TimeStampMixin):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    note = models.ForeignKey(Note, on_delete=models.CASCADE, related_name="likes")

    class Meta:
        unique_together = ("user", "note")
        indexes = [models.Index(fields=["user", "note"])]


# ---------- NoteComment ----------
class NoteComment(TimeStampMixin):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    note = models.ForeignKey(Note, on_delete=models.CASCADE, related_name="comments")
    content = models.TextField()

    class Meta:
        indexes = [models.Index(fields=["note", "created_at"])]


# ---------- NoteChatLog ----------
class NoteChatLog(TimeStampMixin):
    note = models.ForeignKey(Note, on_delete=models.CASCADE, related_name="chat_logs")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_id = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    user_message = models.TextField()
    ai_response = models.TextField()

    class Meta:
        ordering = ["created_at"]
        indexes = [models.Index(fields=["note", "created_at"])]
        models.Index(fields=["session_id"]),

    def save(self, *args, **kwargs):
        # sanitize before saving to prevent stored XSS
        self.user_message = bleach.clean(self.user_message or "", tags=[], strip=True)
        self.ai_response = bleach.clean(self.ai_response or "", tags=[], strip=True)
        super().save(*args, **kwargs)


# ---------- UserNoteLibrary ----------
class UserNoteLibrary(TimeStampMixin):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    note = models.ForeignKey(Note, on_delete=models.CASCADE, related_name="note_library")

    class Meta:
        unique_together = ("user", "note")
        verbose_name = "User Note Library"
        verbose_name_plural = "User Note Libraries"

    def __str__(self):
        return f"{self.user.username} saved {self.note.title}"