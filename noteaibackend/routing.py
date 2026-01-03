from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(
        r"ws/notes/(?P<slug>[\w-]+)/chat/(?P<session_id>[\w-]+)/$",
        consumers.ChatConsumer.as_asgi()
    ),
]