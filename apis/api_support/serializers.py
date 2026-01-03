import logging
from .models import ContactQuery
from django.conf import settings
from django.core.mail import send_mail
from rest_framework import serializers
from django.utils.html import strip_tags
from django.template.loader import render_to_string

logger = logging.getLogger(__name__)


class ContactQuerySerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    ip_address = serializers.CharField(read_only=True)
    honeypot = serializers.CharField(
        write_only=True, required=False, allow_blank=True, help_text="Leave empty"
    )

    class Meta:
        model = ContactQuery
        fields = [
            'id', 'full_name', 'email', 'message',
            'created_at'
        ]
        read_only_fields = ['ip_address']

    # --- SECURITY FIXES ---
    def validate_full_name(self, value):
        if "\n" in value or "\r" in value:
            raise serializers.ValidationError("Invalid characters in name.")
        return value.strip()

    def validate_email(self, value):
        if "\n" in value or "\r" in value:
            raise serializers.ValidationError("Invalid email format.")
        return value.lower().strip()

    def validate_message(self, value):
        if len(value.strip()) < 10:
            raise serializers.ValidationError("Message must be at least 10 characters long.")
        if len(value) > 2000:
            raise serializers.ValidationError("Message is too long (max 2000 characters).")
        return value.strip()

    def validate_honeypot(self, value):
        """Bots usually fill all fields — block if honeypot has content"""
        if value:
            raise serializers.ValidationError("Invalid submission.")
        return value

    def create(self, validated_data):
        ip_address = validated_data.pop("ip_address", None)
        instance = ContactQuery.objects.create(**validated_data)

        if ip_address:
            instance.ip_address = ip_address
            instance.save(update_fields=["ip_address"])

        # Render HTML + plain text fallback
        try:
        
            html_message = render_to_string("emails/contact_query.html", {
                "full_name": instance.full_name,
                "email": instance.email,
                "message": instance.message,
                "created_at": instance.created_at,
                "ip_address": ip_address or "Unknown",
            })
        
            plain_message = strip_tags(html_message)

            send_mail(
                subject=f"📩 New Contact Query from {instance.full_name}",
                message=plain_message,  # Fallback for plain text clients
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[settings.SUPPORT_EMAIL],
                html_message=html_message,  # HTML version
                fail_silently=True,
            )
        except Exception as e:
            print(f"Email send failed: {e}")

        return instance
