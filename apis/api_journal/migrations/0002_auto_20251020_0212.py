from django.db import migrations, connection
def populate_search_vector(apps, schema_editor):
    Journal = apps.get_model('api_journal', 'Journal')

    with connection.cursor() as cursor:
        for j in Journal.objects.all().iterator():
            combined_text = " ".join(filter(None, [j.summary or "", j.content or ""]))
            # Escape single quotes in the text to prevent SQL errors
            safe_text = combined_text.replace("'", "''")
            cursor.execute(
                "UPDATE api_journal_journal SET search_vector = to_tsvector(%s) WHERE id = %s;",
                [safe_text, j.id],
            )

class Migration(migrations.Migration):
    dependencies = [
        ('api_journal', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(populate_search_vector, reverse_code=migrations.RunPython.noop),
    ]