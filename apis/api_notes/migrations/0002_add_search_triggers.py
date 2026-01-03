from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api_notes", "0001_initial"),  # this is correct
    ]

    operations = [
        migrations.RunSQL(
            """
            -- Enable extension if not already enabled
            CREATE EXTENSION IF NOT EXISTS unaccent;

            -- Trigger for Note search_vector
            CREATE FUNCTION note_search_vector_update() RETURNS trigger AS $$
            BEGIN
                NEW.search_vector :=
                    setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A') ||
                    setweight(to_tsvector('english', coalesce(NEW.content, '')), 'B');
                RETURN NEW;
            END
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER note_search_vector_trigger
            BEFORE INSERT OR UPDATE ON api_notes_note
            FOR EACH ROW EXECUTE FUNCTION note_search_vector_update();

            -- Trigger for Journal search_vector
            CREATE FUNCTION journal_search_vector_update() RETURNS trigger AS $$
            BEGIN
                NEW.search_vector :=
                    setweight(to_tsvector('english', coalesce(NEW.content, '')), 'A') ||
                    setweight(to_tsvector('english', coalesce(NEW.summary, '')), 'B');
                RETURN NEW;
            END
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER journal_search_vector_trigger
            BEFORE INSERT OR UPDATE ON api_notes_journal
            FOR EACH ROW EXECUTE FUNCTION journal_search_vector_update();
            """,
            reverse_sql="""
            DROP TRIGGER IF EXISTS note_search_vector_trigger ON api_notes_note;
            DROP FUNCTION IF EXISTS note_search_vector_update;

            DROP TRIGGER IF EXISTS journal_search_vector_trigger ON api_notes_journal;
            DROP FUNCTION IF EXISTS journal_search_vector_update;
            """,
        ),
    ]
