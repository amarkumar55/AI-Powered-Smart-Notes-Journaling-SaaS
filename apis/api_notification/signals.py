from django.db.models.signals import post_save, post_delete, pre_delete
from django.dispatch import receiver
from .models import Notification
from .cache_utils import invalidate_unread_count

@receiver(post_save, sender=Notification)
def notification_saved(sender, instance, created, **kwargs):
    """Invalidate unread count when notification is created or updated."""
    invalidate_unread_count(instance.user_id)

@receiver(pre_delete, sender=Notification)
def notification_pre_delete(sender, instance, **kwargs):
    # Store necessary info before delete
    instance._cached_user_id = instance.user_id

@receiver(post_delete, sender=Notification)
def notification_deleted(sender, instance, **kwargs):
    user_id = getattr(instance, "_cached_user_id", None)
    if user_id:
        # do whatever you need
        print(f"Notification deleted for user {user_id}")