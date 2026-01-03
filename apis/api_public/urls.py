from django.urls import path
from .views import (FeedView, PopularTagsView, TrendingNotesView, CountryListView,NoteDetail,
    StateListView,
    CityListView,
    TimezoneListView,
    PhoneCodeListView)

urlpatterns = [
    path('feed/', FeedView.as_view(), name='feed'),
    path('note-details/<str:slug>/', NoteDetail.as_view(), name='public-note-details'),
    path('trending/', TrendingNotesView.as_view(), name='trending-notes'),
    path('popular-tags/', PopularTagsView.as_view(), name='trending-notes'),
    path("countries/", CountryListView.as_view(), name="country-list"),
    path("states/<str:country_code>/", StateListView.as_view(), name="state-list"),
    path("cities/<str:state_code>/", CityListView.as_view(), name="city-list"),
    path("timezones/", TimezoneListView.as_view(), name="timezone-list"),
    path("phonecodes/", PhoneCodeListView.as_view(), name="phone-code-list"),
] 