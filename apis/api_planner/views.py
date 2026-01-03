# planner/views.py
from datetime import datetime, timedelta
from django.utils.timezone import get_current_timezone
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from .models import PlannerEntry
from .serializers import PlannerEntrySerializer
from apis.api_auth.utlity import enforce_csrf_if_web


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class PlannerEntryViewSet(viewsets.ModelViewSet):
    """
    A ViewSet for planner entries:
    - list/create: /planner/entries/
    - retrieve/update/delete: /planner/entries/{id}/
    - upcoming_week: /planner/entries/upcoming_week/
    """
    serializer_class = PlannerEntrySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = PlannerEntry.objects.filter(user=self.request.user)

        # Optional filters: ?date_from=YYYY-MM-DD&date_to=YYYY-MM-DD
        df = self.request.query_params.get("date_from")
        dt = self.request.query_params.get("date_to")
        if df:
            qs = qs.filter(date__gte=df)
        if dt:
            qs = qs.filter(date__lte=dt)

        return qs.order_by("date", "start_time")

    def perform_create(self, serializer):
        maybe_csrf = enforce_csrf_if_web(self.request)
        if maybe_csrf is not None:
            return maybe_csrf
        serializer.save(user=self.request.user)

    @action(detail=False, methods=["get"])
    def upcoming_week(self, request):
        """
        Return all entries for the current user from today through the next 6 days.
        Example: /planner/entries/upcoming_week/
        """
        today = datetime.now(tz=get_current_timezone()).date()
        end = today + timedelta(days=6)

        entries = self.get_queryset().filter(date__range=[today, end])
        serialized = self.get_serializer(entries, many=True)

        return Response({
            "date_from": today.isoformat(),
            "date_to": end.isoformat(),
            "entries": serialized.data,
        })
