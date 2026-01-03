import logging
from django.core.cache import cache
from django.db import DatabaseError
from rest_framework.response import Response
from django_ratelimit.decorators import ratelimit
from .serializers import ContactQuerySerializer
from apis.api_support.models import ContactQuery
from django_ratelimit.core import is_ratelimited
from django.utils.decorators import method_decorator
from rest_framework import generics, permissions, status
from apis.api_auth.utlity import enforce_csrf_if_web

logger = logging.getLogger(__name__)



# 🔒 Only admins/staff can view contact queries
@method_decorator(ratelimit(key='user_or_ip', rate='20/m', block=True), name='dispatch')
class ContactQueryListView(generics.ListAPIView):
    serializer_class = ContactQuerySerializer
    permission_classes = [permissions.IsAdminUser]
    
    def get_queryset(self):
        cache_key = "contact_queries"
        qs = cache.get(cache_key)
        if qs is None:
            qs = ContactQuery.objects.all().order_by('-created_at')
            cache.set(cache_key, qs, timeout=60)  # cache for 1 min
        return qs
    

@method_decorator(ratelimit(key='user_or_ip', rate='20/m', block=True), name='dispatch')
class ContactQueryDetailView(generics.RetrieveAPIView):
    serializer_class = ContactQuerySerializer
    lookup_field = 'id'
    permission_classes = [permissions.IsAdminUser]
    
    def get_queryset(self):
        try:
            return ContactQuery.objects.all()
        except DatabaseError as e:
            logger.error(f"DB error while fetching contact query detail: {e}")
            return ContactQuery.objects.none()


# 🌐 Public endpoint, but rate-limited to prevent spam
@method_decorator(ratelimit(key='user_or_ip', rate='5/m', block=True), name='dispatch')  # strict
@method_decorator(ratelimit(key='header:User-Agent', rate='10/m', block=False), name='dispatch')  # soft
class ContactQueryCreateView(generics.CreateAPIView):
    serializer_class = ContactQuerySerializer
    permission_classes = [permissions.AllowAny]

    def dispatch(self, request, *args, **kwargs):
        """Check if UA is rate-limited and log instead of blocking"""
        if is_ratelimited(
            request, group="contactquery-ua", key='header:User-Agent',
            rate='10/m', method="POST", increment=True
        ):
            logger.warning(
                f"🚨 High-frequency UA detected: UA={request.META.get('HTTP_USER_AGENT')} "
                f"IP={request.META.get('REMOTE_ADDR')}"
            )
        return super().dispatch(request, *args, **kwargs)

    def perform_create(self, serializer):
        try:
            serializer.save(ip_address=self.request.META.get('REMOTE_ADDR'))
        except DatabaseError as e:
            logger.error(f"DB error while saving contact query: {e}")
            raise

    def create(self, request, *args, **kwargs):
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            return Response(
                {"detail": "✅ Thanks for contacting us! Our team will get back to you soon."},
                status=status.HTTP_201_CREATED
            )

        except DatabaseError:
            return Response(
                {"error": "A database error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            logger.error(f"Unexpected error in ContactQueryCreateView: {e}")
            return Response(
                {"error": "Something went wrong while submitting your query. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )