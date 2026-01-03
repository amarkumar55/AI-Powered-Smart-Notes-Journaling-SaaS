from django.apps import AppConfig


class NotesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apis.api_notes'
    
    def ready(self):
        import apis.api_notes.signals
