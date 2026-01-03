from datetime import timedelta
from django.utils import timezone
from rest_framework import status
from django.core.cache import cache
from apis.api_notes.models import Note
from apis.api_auth.models import Follow
from rest_framework.views import APIView
from django.db.models import  F, Q
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from apis.api_notes.serializers import NoteSerializer
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated,AllowAny
from functools import reduce
from operator import or_


User = get_user_model()


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class NoteDetail(RetrieveAPIView):
    queryset = Note.objects.all().select_related("user")
    serializer_class = NoteSerializer
    lookup_field = "slug"

    def retrieve(self, request, *args, **kwargs):
        note = self.get_object()  # found via slug

        # Increment view count atomically using pk
        Note.objects.filter(pk=note.pk).update(views_count=F("views_count") + 1)

        # Refresh only the updated field
        note.refresh_from_db(fields=["views_count"])

        serializer = self.get_serializer(note)
        return Response(serializer.data, status=status.HTTP_200_OK)



@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class FeedView(ListAPIView):
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        following_users = Follow.objects.filter(
            follower=user
        ).values_list("following", flat=True)

        notes = (
            Note.objects.filter(user__in=following_users, is_public=True)
            .select_related("user")
            .prefetch_related("images", "tags")  # 🚀 optimize related data
            .only("id", "title", "slug", "content", "created_at", "user_id", "is_public")  
            .order_by("-created_at")
        )

        tag = self.request.query_params.get("tag")

        search = self.request.query_params.get("search")

        if tag:
            notes = notes.filter(tags__icontains=tag)

        if search:
            terms = [term.strip() for term in search.split() if term.strip()]
            notes = notes.filter(
                reduce(or_, [Q(title__icontains=t) | Q(content__icontains=t) for t in terms])
            )

        return notes

    def list(self, request, *args, **kwargs):
        user = request.user
        tag = request.query_params.get("tag", "")
        search = request.query_params.get("search", "")
        page = request.query_params.get("page", 1)

        cache_key = f"feed:{user.id}:{tag}:{search}:page{page}"
        cached_response = cache.get(cache_key)
        if cached_response:
            return Response(cached_response)

        response = super().list(request, *args, **kwargs)

        # Cache full serialized response
        cache.set(cache_key, response.data, timeout=120)  # ⏳ 2 min
        return response


# ---------- TRENDING NOTES ----------
@method_decorator(ratelimit(key="user_or_ip", rate="10/m", block=True), name="dispatch")
class TrendingNotesView(ListAPIView):
    serializer_class = NoteSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        tags_param = self.request.query_params.get("tags")
        period_param = self.request.query_params.get("period")
        search = self.request.query_params.get("search", "").strip()

        qs = (
            Note.objects.filter(is_public=True)
            .select_related("user")
            .prefetch_related("images", "tags")
        )

        if tags_param:
            tags_list = [tag.strip().lower() for tag in tags_param.split(",")]
            qs = qs.filter(tags__name__in=tags_list).distinct()

        if search:
            terms = [term.strip() for term in search.split() if term.strip()]
            qs = qs.filter(
                reduce(or_, [Q(title__icontains=t) | Q(content__icontains=t) for t in terms])
            )

        # default 50 days window
        days = 50
        if period_param:
            try:
                num = int(period_param[:-1])
                unit = period_param[-1]
                if unit == "d":
                    days = num
            except Exception:
                pass

        since = timezone.now() - timedelta(days=days)
        qs = qs.filter(created_at__gte=since)

        return qs.order_by("-trending_score", "-created_at")[:500]

    def list(self, request, *args, **kwargs):
        tags = request.query_params.get("tags", "")
        period = request.query_params.get("period", "7d")
        page = request.query_params.get("page", 1)
        search = request.query_params.get("search", "").strip()

        cache_key = f"trending_notes:{tags}:{period}:search:{search}:page{page}"
        cached = cache.get(cache_key)
        if cached:
            return Response(cached)

        response = super().list(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=300)
        return response




from apis.api_notes.models import Tag
from django.db.models import Sum
# ---------- POPULAR TAGS ----------
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class PopularTagsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        cache_key = "popular_tags:7d"
        cached_tags = cache.get(cache_key)

        if cached_tags:
            return Response(cached_tags)

        since = timezone.now() - timedelta(days=7)

        notes = Note.objects.filter(is_public=True, created_at__gte=since)

        tags = (
            Tag.objects.filter(notes__in=notes)   # ✅ use `notes`
            .annotate(score=Sum("notes__trending_score"))  # ✅ correct join
            .order_by("-score")[:10]
        )

        data = [{"name": t.name, "score": t.score or 0} for t in tags]
        cache.set(cache_key, data, timeout=86400)  # cache for 1 day

        return Response(data)


from core.location_loader import (
    get_all_countries,
    get_states_by_country,
    get_cities_by_state,
    get_all_timezone,
    get_all_code,
)


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class CountryListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        countries = get_all_countries()
        return Response(countries, status=status.HTTP_200_OK)



@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class StateListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, country_code):
        states = get_states_by_country(country_code.upper())
        if not states:
            return Response(
                {"error": "No states found for this country"},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(states, status=status.HTTP_200_OK)



@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class CityListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, state_code):
        cities = get_cities_by_state(state_code.upper())
        if not cities:
            return Response(
                {"error": "No cities found for this state"},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(cities, status=status.HTTP_200_OK)



@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class TimezoneListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        timezones = get_all_timezone()
        return Response(timezones, status=status.HTTP_200_OK)


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class PhoneCodeListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        
        try:
            phone_codes = get_all_code()
            return Response(phone_codes, status=status.HTTP_200_OK)
        except Exception as e:
            print(str(e))
            