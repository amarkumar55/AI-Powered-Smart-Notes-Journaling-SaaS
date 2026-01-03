from .models import Notification
from rest_framework import serializers
from apis.api_auth.serializers import UserPublicSerializer

class NotificationSerializer(serializers.ModelSerializer):
    user = UserPublicSerializer(read_only=True)

    class Meta:
        model = Notification
        fields = [
            "id",
            "user",
            "notification_type",
            "title",
            "message",
            "is_read",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "user",
            "notification_type",
            "title",
            "message",
            "is_read",
            "created_at",
        ]
