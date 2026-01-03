from django.urls import path
from .views import ContactQueryListView, ContactQueryDetailView, ContactQueryCreateView

urlpatterns = [
    path('', ContactQueryListView.as_view(), name='api_support_contact_list'),
    path('contact/create/', ContactQueryCreateView.as_view(), name='api_support_contact_create'),
    path('<int:id>/', ContactQueryDetailView.as_view(), name='api_support_contact_detail'),

] 