from django.core.cache import cache
from .models import Notification

def get_unread_count(user_id):
    """Return cached unread count (DB fallback if not cached)."""
    key = f"notifications:{user_id}:unread_count"
    count = cache.get(key)
    if count is None:
        count = Notification.objects.filter(user_id=user_id, is_read=False).count()
        cache.set(key, count, timeout=300)  # cache for 5 minutes
    return count

def invalidate_unread_count(user_id):
    """Delete cache key so it's recalculated on next request."""
    cache.delete(f"notifications:{user_id}:unread_count")
