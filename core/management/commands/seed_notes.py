# apis/api_notes/management/commands/seed_notes.py
import random
import uuid
from django.core.management.base import BaseCommand
from django.utils.text import slugify
from faker import Faker
from django.contrib.auth import get_user_model
from apis.api_notes.models import Note, Tag

User = get_user_model()
fake = Faker()

class Command(BaseCommand):
    help = "Generate fake notes with random users and tags"

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=20,
            help="Number of fake notes to create (default: 20)",
        )

    def handle(self, *args, **options):
        count = options["count"]

        users = list(User.objects.all())
        if not users:
            self.stdout.write(self.style.ERROR("❌ No users found. Please create at least 1 user."))
            return

        # Pre-create some fake tags if not exist
        sample_tags = ["django", "python", "notes", "productivity", "ai", "music", "study"]
        for tag_name in sample_tags:
            Tag.objects.get_or_create(name=tag_name)

        tags = list(Tag.objects.all())

        for _ in range(count):
            user = random.choice(users)
            title = fake.sentence(nb_words=6)
            content = fake.paragraph(nb_sentences=10)

            slug = f"{slugify(title)[:80]}-{uuid.uuid4().hex[:10]}"

            note = Note.objects.create(
                user=user,
                title=title,
                slug=slug,
                content=content,
                is_public=random.choice([True, False]),
                type=random.choice([choice[0] for choice in Note.NOTE_TYPE_CHOICES]),
                views_count=random.randint(0, 200),
                likes_count=random.randint(0, 50),
                comments_count=random.randint(0, 20),
                shares_count=random.randint(0, 10),
                trending_score=random.randint(0, 100),
            )

            # attach random tags
            note.tags.add(*random.sample(tags, k=random.randint(1, min(3, len(tags)))))

        self.stdout.write(self.style.SUCCESS(f"✅ Successfully created {count} fake notes."))
