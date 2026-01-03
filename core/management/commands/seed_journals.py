# apis/api_notes/management/commands/seed_journals.py
import random
from django.core.management.base import BaseCommand
from faker import Faker
from django.contrib.auth import get_user_model
from apis.api_journal.models import Journal, JournalImage

User = get_user_model()
fake = Faker()

MOODS = ["happy", "sad", "excited", "angry", "calm", "stressed", "grateful"]
THEMES = ["work", "relationships", "health", "travel", "family", "personal growth"]

class Command(BaseCommand):
    help = "Generate fake journals with optional images"

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=20,
            help="Number of fake journals to create (default: 20)",
        )
        parser.add_argument(
            "--images",
            type=int,
            default=0,
            help="Number of random images per journal (default: 0)",
        )

    def handle(self, *args, **options):
        count = options["count"]
        image_count = options["images"]

        users = list(User.objects.all())
        if not users:
            self.stdout.write(self.style.ERROR("❌ No users found. Please create at least 1 user."))
            return

        for _ in range(count):
            user = random.choice(users)
            content = fake.paragraph(nb_sentences=12)
            summary = fake.sentence(nb_words=12)

            journal = Journal.objects.create(
                user=user,
                content=content,
                summary=summary,
                mood=random.choice(MOODS),
                themes=random.sample(THEMES, k=random.randint(1, 3)),
                suggestions=[fake.sentence() for _ in range(random.randint(1, 3))],
                prompt=fake.sentence(),
            )

            # Add fake images (if requested)
            for _ in range(image_count):
                JournalImage.objects.create(
                    journal=journal,
                    image=f"journal_images/{fake.file_name(extension='jpg')}",  # ⚠️ generates fake path, not real file
                    caption=fake.sentence(),
                )

        self.stdout.write(self.style.SUCCESS(f"✅ Successfully created {count} fake journals with up to {image_count} images each."))
