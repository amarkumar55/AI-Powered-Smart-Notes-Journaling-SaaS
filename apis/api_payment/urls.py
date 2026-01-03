from django.urls import path

from .views import (
    PaymentListView, PaymentDetailView, PaymentProcessView,
    RefundListView, RefundDetailView
)

urlpatterns = [
    path('list/', PaymentListView.as_view(), name='api_payment_list'),
    path('<uuid:id>/', PaymentDetailView.as_view(), name='api_payment_detail'),
    path('process/', PaymentProcessView.as_view(), name='api_payment_process'),
    path('refunds/', RefundListView.as_view(), name='api_refund_list'),
    path('refunds/<uuid:id>/', RefundDetailView.as_view(), name='api_refund_detail'),
] 