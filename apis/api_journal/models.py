from django.db import models
from django.contrib.auth import get_user_model
from apis.api_auth.models import TimeStampMixin
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from encrypted_model_fields.fields import EncryptedTextField
from core.note_processor import ai_generate_journal_insights


User = get_user_model()

# Create your models here.
# ---------- Journal ----------
class Journal(TimeStampMixin):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="journals", db_index=True)
    content = EncryptedTextField()
    summary = EncryptedTextField(blank=True, null=True)
    mood = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    themes = models.JSONField(blank=True, null=True)
    suggestions = models.JSONField(blank=True, null=True)
    prompt = models.TextField(blank=True, null=True)
    search_vector = SearchVectorField(null=True, editable=False)

    class Meta:
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["mood"]),
            GinIndex(fields=["search_vector"]),
        ]

    def generate_insights(self):
        # AI-generated insights can be expensive — consider background job
        insights = ai_generate_journal_insights(self.content)
        # store insights in suggestions or separate field if present
        self.suggestions = insights.get("suggestions") if isinstance(insights, dict) else self.suggestions
        self.save(update_fields=["suggestions"])
        return insights

    def save(self, *args, **kwargs):
        """
        Update search_vector with decrypted text before saving.
        """
        # Only build search vector if summary/content exist
    
        combined_text = " ".join(
            filter(None, [self.summary or "", self.content or ""])
        )

        # You can compute the search vector via SearchVector
        # Note: SearchVector() returns SQL expression, not direct value.
        # So instead, use a raw function call.
        from django.contrib.postgres.search import SearchVector
        self.search_vector = SearchVector(
            value=combined_text,
            config='english'
        )
        super().save(*args, **kwargs)



class JournalImage(models.Model):
    journal = models.ForeignKey(Journal, on_delete=models.CASCADE, related_name="images")
    image = models.ImageField(upload_to="journal_images/")
    caption = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)