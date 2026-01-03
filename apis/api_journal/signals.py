from django.db.models.signals import post_delete
from django.dispatch import receiver
from .models import JournalImage

@receiver(post_delete, sender=JournalImage)
def delete_image_file(sender, instance, **kwargs):
    """
    Deletes file from storage when JournalImage is deleted.
    """
    if instance.image and instance.image.storage.exists(instance.image.name):
        try:
            instance.image.delete(save=False)
        except Exception:
            # Fail silently to avoid breaking journal deletion
            pass