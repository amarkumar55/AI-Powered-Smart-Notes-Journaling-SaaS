from django.urls import path
from .views import PlannerEntryViewSet

planner_list = PlannerEntryViewSet.as_view({
    "get": "list",
    "post": "create",
})

planner_detail = PlannerEntryViewSet.as_view({
    "get": "retrieve",
    "put": "update",
    "patch": "partial_update",
    "delete": "destroy",
})

planner_week = PlannerEntryViewSet.as_view({
    "get": "upcoming_week",
})

urlpatterns = [
    path("planner/entries/", planner_list, name="planner-entries"),
    path("planner/entries/<int:pk>/", planner_detail, name="planner-entry-detail"),
    path("planner/upcoming_week/", planner_week, name="planner-week"),
]
