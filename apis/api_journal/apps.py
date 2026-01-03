from django.apps import AppConfig

class ApiJournalConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apis.api_journal'
    def ready(self):
        import apis.api_journal.signals
