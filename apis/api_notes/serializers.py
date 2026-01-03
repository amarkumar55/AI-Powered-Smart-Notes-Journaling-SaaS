from PIL import Image
from .models import UserNoteLibrary
from rest_framework import serializers
from django.contrib.auth import get_user_model
from apis.api_auth.serializers import UserPublicSerializer
from .models import Note, NoteComment, NoteChatLog, NoteImage, NoteTag, Tag

User = get_user_model()


class NoteImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = NoteImage
        fields = ["image"]
        read_only_fields = ["id", "created_at"]

    def validate_image(self, image):
        # Max size 5MB
        if image.size > 5 * 1024 * 1024:
            raise serializers.ValidationError("Each image must be <= 5MB")

        # Allowed types (MIME check)
        valid_mime_types = ["image/jpeg", "image/png", "image/jpg"]
        if image.content_type not in valid_mime_types:
            raise serializers.ValidationError("Unsupported image type")

        # File spoofing protection (verify actual file signature)
        try:
            Image.open(image).verify()
        except Exception:
            raise serializers.ValidationError("Uploaded file is not a valid image.")

        return image


class NoteSerializer(serializers.ModelSerializer):
    images = NoteImageSerializer(many=True, read_only=True)
    user = UserPublicSerializer(read_only=True)
    liked = serializers.SerializerMethodField()


    uploaded_images = serializers.ListField(
        child=serializers.ImageField(max_length=None, allow_empty_file=False, use_url=False),
        write_only=True,
        required=False,
    )
    tags = serializers.ListField(
        child=serializers.CharField(max_length=50),
        write_only=True,
        required=False,
    )
    
    class Meta:
        model = Note
        fields = [
            "title",
            "slug",
            "content",
            "tags",
            "is_public",
            "is_publish",
            "created_at",
            "views_count",
            "likes_count",
            "comments_count",
            "shares_count",
            "images",
            "uploaded_images",
            "user",
            "liked",
        ]
        read_only_fields = ["created_at", "slug"]

    def get_is_shareable(self, obj):
        return obj.is_public
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        
        # If it's a private note, remove user
        if not instance.is_public:
            data.pop("user", None)
        
        return data

    def validate_uploaded_images(self, images):
        if len(images) > 5:
            raise serializers.ValidationError("You can upload a maximum of 5 images.")
        for img in images:
            if img.size > 5 * 1024 * 1024:
                raise serializers.ValidationError(f"{img.name} is too large (max 5MB).")
            if img.content_type not in ["image/jpeg", "image/png", "image/jpg"]:
                raise serializers.ValidationError(f"{img.name} has unsupported type.")
            # Extra spoofing check
            try:
                Image.open(img).verify()
            except Exception:
                raise serializers.ValidationError(f"{img.name} is not a valid image file.")
        return images

    def create(self, validated_data):
        tag_names = validated_data.pop("tags", [])
        uploaded_images = validated_data.pop("uploaded_images", [])

        # Let the model handle slug auto-generation if not provided
        note = Note.objects.create(**validated_data)

        # Handle tags (deduplicate & normalize)
        tag_names = {name.strip().lower() for name in tag_names if name.strip()}
        for name in tag_names:
            tag, _ = Tag.objects.get_or_create(name=name)
            NoteTag.objects.get_or_create(note=note, tag=tag)

        # Handle images with bulk_create for performance
        note_images = [NoteImage(note=note, image=img) for img in uploaded_images]
        if note_images:
            NoteImage.objects.bulk_create(note_images)

        return note
    
    def get_liked(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            return obj.likes.filter(user=user).exists()
        return False
    

class NoteCommentSerializer(serializers.ModelSerializer):
    user = UserPublicSerializer(read_only=True)
    class Meta:
        model = NoteComment
        fields = ['id','user', 'note', 'content', 'updated_at']
        read_only_fields = ['id','user', 'note', 'updated_at']


    
class NoteSummarySerializer(serializers.Serializer):
    title = serializers.CharField()
    summary = serializers.CharField()


class NoteChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = NoteChatLog
        fields = ['user_message', 'ai_response']
        read_only_fields = ['ai_response']

class NoteChatLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = NoteChatLog
        fields = ['id', 'user_message', 'ai_response', 'updated_at']



class UserNoteLibrarySerializer(serializers.ModelSerializer):
    note_title = serializers.CharField(source="note.title", read_only=True)
    note_slug = serializers.CharField(source="note.slug", read_only=True)

    class Meta:
        model = UserNoteLibrary
        fields = ["note_slug", "note_title"]
        read_only_fields = ["note_slug", "note_title"]