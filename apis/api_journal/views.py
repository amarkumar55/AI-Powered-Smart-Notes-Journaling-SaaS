from .serializers import JournalSerializer
from .models import Journal
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from apis.api_auth.utlity import enforce_csrf_if_web
from django.db.models import  F
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.permissions import IsAuthenticated
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django.contrib.postgres.search import SearchQuery, SearchRank

@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class JournalListCreate(ListCreateAPIView):
    serializer_class = JournalSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def initial(self, request, *args, **kwargs):
        maybe = enforce_csrf_if_web(request)
        if maybe is not None:
            return maybe
        return super().initial(request, *args, **kwargs)

    def get_queryset(self):
        qs = (
            Journal.objects.filter(user=self.request.user)
            .prefetch_related("images")
            .order_by("-created_at")
        )

        search = self.request.query_params.get("search", "").strip()

        if search:
            # Use PostgreSQL full-text search
            query = SearchQuery(search)
            qs = qs.annotate(rank=SearchRank(F("search_vector"), query))
            qs = qs.filter(search_vector=query).order_by("-rank", "-created_at")

        return qs

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class JournalDetail(RetrieveUpdateDestroyAPIView):
    serializer_class = JournalSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "pk"

    def get_queryset(self):
        return Journal.objects.filter(user=self.request.user).prefetch_related("images")
