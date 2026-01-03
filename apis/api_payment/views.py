from django.db import models
from .audit import log_payment_event
from django.db import transaction
from rest_framework.views import APIView
from rest_framework.response import Response
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from apis.api_payment.models import Payment, Refund
from rest_framework import generics, permissions, status
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import BasePermission
from apis.api_auth.utlity import  enforce_csrf_if_web 
from .serializers import PaymentSerializer, RefundSerializer, PaymentProcessSerializer, RefundRequestSerializer


class IsPaymentOwner(BasePermission):

    def has_object_permission(self, request, view, obj):
        # Payment object case
        if hasattr(obj, "user"):
            return obj.user == request.user
        # Refund object case
        if hasattr(obj, "payment"):
            return obj.payment.user == request.user
        return False

# ----------------------------
# Payment Views
# ----------------------------

@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class PaymentListView(generics.ListAPIView):
    serializer_class = PaymentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Payment.objects.filter(
            user=self.request.user
        ).order_by('-created_at')


@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class PaymentDetailView(generics.RetrieveAPIView):
    serializer_class = PaymentSerializer
    permission_classes = [permissions.IsAuthenticated,IsPaymentOwner]
    lookup_field = 'id'

    def get_queryset(self):
        return Payment.objects.filter(user=self.request.user)


# ----------------------------
# Refund Views
# ----------------------------
@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class RefundListView(generics.ListAPIView):
    serializer_class = RefundSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Refund.objects.filter(payment__user=self.request.user).select_related("payment").order_by("-created_at")



@method_decorator(ratelimit(key="user_or_ip", rate="5/m", block=True), name="dispatch")
class RefundDetailView(generics.RetrieveAPIView):
    serializer_class = RefundSerializer
    permission_classes = [permissions.IsAuthenticated, IsPaymentOwner]
    lookup_field = 'id'

    def get_queryset(self):
        return Refund.objects.filter(payment__user=self.request.user)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key='user_or_ip', rate='5/m', block=True), name='dispatch')
class PaymentProcessView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Enforce CSRF only for cookie-authenticated clients
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf
        
    
        serializer = PaymentProcessSerializer(data=request.data)
        if not serializer.is_valid():
            log_payment_event(
                request,
                action="payment_create",
                outcome="failure",
                message=f"validation_error: {serializer.errors}"
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        try:
            payment = Payment.objects.create(
                user=request.user,
                amount=data['amount'],
                currency=data['currency'],
                status='pending',
                payment_method=data['payment_method'],
                description=data.get('description', '')
            )
            log_payment_event(
                request,
                action="payment_create",
                outcome="success",
                message="payment created (pending)",
                payment_id=str(payment.id),
                amount=payment.amount,
                currency=payment.currency,
            )
            return Response(PaymentSerializer(payment).data, status=status.HTTP_201_CREATED)

        except Exception as e:
            log_payment_event(
                request,
                action="payment_create",
                outcome="failure",
                message=f"exception: {str(e)}",
            )
            return Response({"error": "Failed to create payment."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key='user_or_ip', rate='5/m', block=True), name='dispatch')
class RefundRequestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Enforce CSRF only for cookie-authenticated clients
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        serializer = RefundRequestSerializer(data=request.data)
        if not serializer.is_valid():
            log_payment_event(
                request,
                action="refund_request",
                outcome="failure",
                message=f"validation_error: {serializer.errors}"
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data

        try:
            with transaction.atomic():
                # 🔒 Lock the payment row for this transaction
                payment = Payment.objects.select_for_update().get(
                    user=request.user,
                    id=data["payment_id"],
                    status="paid",
                )

                # prevent over-refund
                total_refunded = Refund.objects.filter(payment=payment).aggregate(
                    total=models.Sum("amount")
                )["total"] or 0

                if total_refunded + data["amount"] > payment.amount:
                    log_payment_event(
                        request,
                        action="refund_request",
                        outcome="failure",
                        message="over_refund_attempt",
                        payment_id=str(payment.id),
                        amount=data["amount"],
                        currency=payment.currency,
                    )
                    return Response(
                        {"error": "Refund exceeds original payment."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # ✅ create refund safely within the locked transaction
                refund = Refund.objects.create(
                    payment=payment,
                    amount=data["amount"],
                    status="pending",
                )

            # success logging (outside atomic to avoid rollback affecting logs)
            log_payment_event(
                request,
                action="refund_request",
                outcome="success",
                message="refund created (pending)",
                payment_id=str(payment.id),
                refund_id=str(refund.id),
                amount=refund.amount,
                currency=payment.currency,
            )
            return Response(
                RefundSerializer(refund).data,
                status=status.HTTP_201_CREATED,
            )

        except Payment.DoesNotExist:
            return Response(
                {"error": "Payment not found or not eligible for refund."},
                status=status.HTTP_404_NOT_FOUND,
            )

        except Exception as e:
            log_payment_event(
                request,
                action="refund_request",
                outcome="failure",
                message=f"exception: {str(e)}",
                payment_id=data.get("payment_id"),
                amount=data.get("amount"),
            )
            return Response(
                {"error": "Failed to create refund."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )