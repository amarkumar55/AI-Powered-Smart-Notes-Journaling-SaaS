from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import NotificationListView, NotificationDetailView, NotificationActionViewSet

router = DefaultRouter()

router.register(r"actions", NotificationActionViewSet, basename="notification-actions")

urlpatterns = [
    path("list/", NotificationListView.as_view(), name="notification-list"),
    path("<int:pk>/", NotificationDetailView.as_view(), name="notification-detail"),
    path("", include(router.urls)),
]