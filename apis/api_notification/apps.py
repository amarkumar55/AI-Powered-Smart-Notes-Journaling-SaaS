from django.apps import AppConfig


class ApiNotifiactionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apis.api_notification'
    def ready(self):
        import apis.api_notification.signals  