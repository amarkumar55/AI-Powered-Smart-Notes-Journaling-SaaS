import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "noteaibackend.settings")

# Initialize Django apps first
django_asgi_app = get_asgi_application()

# Delay websocket imports until after apps are loaded
from noteaibackend.routing import websocket_urlpatterns
from .middleware import MultiAuthMiddleware

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": MultiAuthMiddleware(
        URLRouter(websocket_urlpatterns)
    ),
})