from PIL import Image
from rest_framework import serializers
from django.db import transaction
from .models import JournalImage, Journal

MAX_IMAGE_SIZE_MB = 5
MAX_IMAGE_PIXELS = 8000 * 8000  # ~64Mpx safety cap
MAX_IMAGES_PER_JOURNAL = 10


class JournalImageSerializer(serializers.ModelSerializer):
    def validate_image(self, image):
        # --- File size ---
        if image.size > MAX_IMAGE_SIZE_MB * 1024 * 1024:
            raise serializers.ValidationError(f"Each image must be <= {MAX_IMAGE_SIZE_MB}MB")

        # --- Verify actual image content ---
        try:
            img = Image.open(image)
            img.verify()  # Verify header + corruption
            img.close()

            # reopen for dimension check (verify() closes the file)
            img = Image.open(image)
            width, height = img.size
            if width * height > MAX_IMAGE_PIXELS:
                raise serializers.ValidationError(
                    f"Image dimensions too large ({width}x{height}). Max allowed is {MAX_IMAGE_PIXELS:,} pixels total."
                )
        except Exception:
            raise serializers.ValidationError("Uploaded file is not a valid image.")

        return image

    class Meta:
        model = JournalImage
        fields = ["id", "image", "caption", "created_at"]
        read_only_fields = ["id", "created_at"]


class JournalSerializer(serializers.ModelSerializer):
    images = JournalImageSerializer(many=True, read_only=True)
    uploaded_images = serializers.ListField(
        child=serializers.ImageField(max_length=100000, allow_empty_file=False, use_url=False),
        write_only=True,
        required=False,
    )

    class Meta:
        model = Journal
        fields = [
            "id", "content", "summary", "mood", "themes", "suggestions",
            "prompt", "created_at", "updated_at", "images", "uploaded_images"
        ]

    def validate_uploaded_images(self, images):
        """ Enforce max number of images per journal """
        instance = getattr(self, "instance", None)
        existing_count = instance.images.count() if instance else 0
        if existing_count + len(images) > MAX_IMAGES_PER_JOURNAL:
            raise serializers.ValidationError(
                f"You can upload at most {MAX_IMAGES_PER_JOURNAL} images per journal."
            )
        return images

    @transaction.atomic
    def create(self, validated_data):
        uploaded_images = validated_data.pop("uploaded_images", [])
        journal = Journal.objects.create(**validated_data)
        for image in uploaded_images:
            JournalImage.objects.create(journal=journal, image=image)
        return journal

    @transaction.atomic
    def update(self, instance, validated_data):
        uploaded_images = validated_data.pop("uploaded_images", [])
        instance = super().update(instance, validated_data)
        for image in uploaded_images:
            JournalImage.objects.create(journal=instance, image=image)
        return instance
