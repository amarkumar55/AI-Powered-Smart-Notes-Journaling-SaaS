# planner/signals.py (optional later)
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import PlannerEntry
from apis.api_notification.models import Notification  

@receiver(post_save, sender=PlannerEntry)
def schedule_entry_notification(sender, instance, created, **kwargs):
    if instance.want_notification:
        when = instance.get_reminder_datetime()
        if when:
            Notification.objects.get_or_create(
                user=instance.user,
                defaults={"title": instance.title, "message": instance.description[:200], "scheduled_for": when},
            )
