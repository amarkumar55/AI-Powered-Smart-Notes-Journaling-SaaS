from .models import Notification
from rest_framework import status
from django.utils import timezone
from rest_framework import viewsets
from rest_framework import mixins
from rest_framework.response import Response
from rest_framework.decorators import action
from .serializers import NotificationSerializer
from django_ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import ListAPIView, RetrieveAPIView
from apis.api_auth.utlity import  enforce_csrf_if_web 



@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NotificationListView(ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = Notification.objects.filter(user=self.request.user).order_by("-created_at")
        
        # Optional filter by is_read query param
        is_read = self.request.query_params.get("is_read")
        if is_read is not None:
            if is_read.lower() == "true":
                qs = qs.filter(is_read=True)
            elif is_read.lower() == "false":
                qs = qs.filter(is_read=False)

        return qs
    
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)

        unread_count = Notification.objects.filter(
            user=request.user, is_read=False
        ).count()

        # use paginator to get base pagination structure
        paginated_response = self.get_paginated_response(serializer.data)
        
        # add unread_count at root level
        paginated_response.data["unread_count"] = unread_count
        
        return paginated_response


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NotificationDetailView(RetrieveAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).only(
            "notification_type", "title", "message", "is_read", "created_at"
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()

        # Optional: auto mark read
        if request.query_params.get("mark_read") == "true" and not instance.is_read:
            instance.is_read = True
            instance.read_at = timezone.now()
            instance.save(update_fields=["is_read", "read_at"])

        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NotificationActionViewSet(mixins.DestroyModelMixin, viewsets.GenericViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def dispatch(self, request, *args, **kwargs):
        # Enforce CSRF only for cookie-authenticated clients
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        # Always scoped to current user, and include fields needed for updates
        return Notification.objects.filter(user=self.request.user).only(
            "id", "is_read", "read_at"
        )

    @action(detail=False, methods=["post"])
    def mark_all_read(self, request):
        count = Notification.objects.filter(user=request.user, is_read=False).update(
            is_read=True, read_at=timezone.now()
        )
        return Response({"status": f"{count} notifications marked as read."})

    @action(detail=True, methods=["post"])
    def mark_one_read(self, request, pk=None):
        notification = self.get_object()
        if not notification.is_read:
            notification.is_read = True
            notification.read_at = timezone.now()
            notification.save(update_fields=["is_read", "read_at"])
        return Response(
            {"status": f"Notification {notification.id} marked as read."},
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance_id = instance.id
        self.perform_destroy(instance)
        return Response(
            {"status": f"Notification {instance_id} deleted."},
            status=status.HTTP_200_OK,
        )