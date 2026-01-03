from django.urls import path
from .views import JournalListCreate, JournalDetail

urlpatterns = [
    path("", JournalListCreate.as_view(), name="journals-list"),
    path("<int:pk>/", JournalDetail.as_view(), name="journals-detail"),
]