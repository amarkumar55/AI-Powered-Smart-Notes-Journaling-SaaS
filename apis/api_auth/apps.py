from django.apps import AppConfig


class ApiAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apis.api_auth'
    def ready(self):
        import apis.api_auth.signals
