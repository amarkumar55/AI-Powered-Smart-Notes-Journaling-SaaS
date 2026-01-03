from django.urls import path
from .views import PlanListView, PlanDetailView, RazorpayCheckoutView, AssignPlanView

urlpatterns = [
    path('plans/', PlanListView.as_view(), name='plan-list'),
    path('plans/<slug:slug>/', PlanDetailView.as_view(), name='plan-detail'),
    path('checkout/', RazorpayCheckoutView.as_view(), name='razorpay-checkout'),
    path('assign/', AssignPlanView.as_view(), name='assign-plan'),
] 