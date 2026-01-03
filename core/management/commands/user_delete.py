from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import timedelta

User = get_user_model()

def delete_expired_accounts():
    cutoff = timezone.now() - timedelta(days=30)
    expired_users = User.objects.filter(is_active=False, updated_at__lte=cutoff)
    count = expired_users.count()
    expired_users.delete()
    return count