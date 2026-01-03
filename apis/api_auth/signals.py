from django.db.models import F
from django.conf import settings
from django.dispatch import receiver
from .models import CustomUser, Wallet, Follow
from django.db.models.signals import post_save, post_delete

@receiver(post_save, sender=CustomUser)
def create_user_wallet(sender, instance, created, **kwargs):
    if created:
        wallet = Wallet.objects.create(user=instance)

        # Signup Bonus
        initial_credit = getattr(settings, "DEFAULT_FREE_CREDIT", 10000)
        wallet.credit_from_register(initial_credit)


@receiver(post_save, sender=Follow)
def update_follow_counts_on_create(sender, instance, created, **kwargs):
    if created:
        instance.follower.following_count = F('following_count') + 1
        instance.follower.save(update_fields=['following_count'])
        instance.following.followers_count = F('followers_count') + 1
        instance.following.save(update_fields=['followers_count'])


@receiver(post_delete, sender=Follow)
def update_follow_counts_on_delete(sender, instance, **kwargs):
    instance.follower.following_count = F('following_count') - 1
    instance.follower.save(update_fields=['following_count'])
    instance.following.followers_count = F('followers_count') - 1
    instance.following.save(update_fields=['followers_count'])