from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import render
from django.http import HttpResponseNotFound
from django.http import JsonResponse

def root_invalid_endpoint(request):
    return JsonResponse({
        "error": "Invalid endpoint. Please use /api/1.0/..."
    }, status=404)


urlpatterns = [     
    path('api/1.0/auth/', include('apis.api_auth.urls')), 
    path('api/1.0/notes/', include('apis.api_notes.urls')), 
    path('api/1.0/journals/', include('apis.api_journal.urls')),  
    path('api/1.0/notifications/', include('apis.api_notification.urls')),  
    path('api/1.0/subscription/', include('apis.api_subscription.urls')),  
    path('api/1.0/public/', include('apis.api_public.urls')),
    path('api/1.0/payments/', include('apis.api_payment.urls')),
    path('api/1.0/support/', include('apis.api_support.urls')),
    path("api/1.0/week/", include("apis.api_planner.urls")),
    path('', root_invalid_endpoint),
]


# Serve media files in dev only
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


# --- Custom Error Handlers ---
def custom_permission_denied_view(request, exception):
    return render(request, "403.html", status=403)


def custom_404(request, exception=None):
    return HttpResponseNotFound("The page you are looking for does not exist.")


def custom_500_view(request):
    return render(request, "500.html", status=500)


handler403 = "noteaibackend.urls.custom_permission_denied_view"
handler404 = "noteaibackend.urls.custom_404"
handler500 = "noteaibackend.urls.custom_500_view"
