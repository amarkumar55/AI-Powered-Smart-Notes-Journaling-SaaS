import razorpay
import logging
from django.db import transaction
from django.conf import settings
from core.helper import store_activity
from django.core.mail import send_mail
from apis.api_auth.models import Wallet
from .serializers import PlanSerializer
from rest_framework.views import APIView
from django.utils.html import strip_tags
from rest_framework.response import Response
from apis.api_subscription.models import Plan
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.views.decorators.cache import cache_page
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from apis.api_auth.utlity import enforce_csrf_if_web
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, permissions, status
from .serializers import PlanSerializer, UserTransactionSerializer
from apis.api_subscription.models import UserTransaction, PlanPurchase

logger = logging.getLogger(__name__)

razorpay_client = razorpay.Client(auth=(settings.RAZOR_KEY_ID, settings.RAZOR_KEY_SECRET))


# ----------------------------
# Public Plans
# ----------------------------
@method_decorator(ratelimit(key='user_or_ip', rate='30/m', block=True), name='dispatch')
@method_decorator(cache_page(60 * 5), name='dispatch')   # cache for 5 minutes
class PlanListView(generics.ListAPIView):
    queryset = Plan.objects.filter(is_active=True)
    serializer_class = PlanSerializer
    permission_classes = [permissions.AllowAny]


@method_decorator(ratelimit(key='user_or_ip', rate='30/m', block=True), name='dispatch')
@method_decorator(cache_page(60 * 5), name='dispatch')   # cache for 5 minutes
class PlanDetailView(generics.RetrieveAPIView):
    queryset = Plan.objects.filter(is_active=True)
    serializer_class = PlanSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'slug'


# ----------------------------
# User Transactions (private, no caching!)
# ----------------------------
@method_decorator(ratelimit(key='user_or_ip', rate='3/m', block=True), name='dispatch')
class UserTransactionListView(generics.ListAPIView):
    serializer_class = UserTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return (
            UserTransaction.objects.filter(user=self.request.user)
            .order_by('-transaction_date')
        )


@method_decorator(ratelimit(key='user_or_ip', rate='3/m', block=True), name='dispatch')
class UserTransactionDetailView(generics.RetrieveAPIView):
    serializer_class = UserTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):
        return UserTransaction.objects.filter(user=self.request.user)
    
@method_decorator(ratelimit(key='user_or_ip', rate='10/m', block=True), name='dispatch')
class RazorpayCheckoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        plan_id = request.data.get("plan_id")
        plan = get_object_or_404(Plan, id=plan_id, is_active=True)

        user = request.user
        amount = int(float(plan.price) * 100)  # Razorpay expects paise

        try:
        
            currency = getattr(plan, "currency", "INR")

            order_data = {
                "amount": amount,
                "currency": currency,
                "receipt": f"subscription_{plan.id}_{user.id}",
                "notes": {
                    "plan_id": str(plan.id),
                    "user_id": str(user.id),
                },
            }

        
            order = razorpay_client.order.create(data=order_data)

    
            logger.info(
                "Razorpay order created",
                extra={
                    "user_id": user.id,
                    "plan_id": str(plan.id),
                    "order_id": order.get("id"),
                    "amount": amount,
                    "currency": currency,
                },
            )

        
            plan_data = {
                "id": str(plan.id),
                "slug": plan.slug,
                "title": plan.title,
                "price": str(plan.price),
            }

            return Response(
                {
                    "order_id": order["id"],
                    "amount": order["amount"],
                    "currency": order["currency"],
                    "key": settings.RAZOR_KEY_ID,  # ✅ only public key exposed
                    "email": user.email,
                    "contact": getattr(getattr(user, "profile", None), "cell", ""),
                    "name": f"{user.first_name} {user.last_name}".strip(),
                    "plan": plan_data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(
                "Razorpay order creation failed",
                extra={
                    "user_id": user.id,
                    "plan_id": str(plan.id),
                    "error": str(e),
                },
            )
            return Response(
                {"error": "Failed to create Razorpay order."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    
@method_decorator(ratelimit(key="user_or_ip", rate="3/m", block=True), name="dispatch")
class AssignPlanView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        maybe_csrf = enforce_csrf_if_web(request)
        if maybe_csrf is not None:
            return maybe_csrf

        user = request.user
        plan_id = request.data.get("plan_id")
        razorpay_payment_id = request.data.get("razorpay_payment_id")
        razorpay_order_id = request.data.get("razorpay_order_id")
        razorpay_signature = request.data.get("razorpay_signature")

        plan = get_object_or_404(Plan, id=plan_id, is_active=True)
        client = razorpay.Client(auth=(settings.RAZOR_KEY_ID, settings.RAZOR_KEY_SECRET))

        # ✅ Verify signature
        params_dict = {
            "razorpay_order_id": razorpay_order_id,
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_signature": razorpay_signature,
        }
        try:
            client.utility.verify_payment_signature(params_dict)
        except Exception:
            return Response({"error": "Payment verification failed"}, status=400)

        try:
            with transaction.atomic():
                # ✅ Fetch and validate Razorpay payment
                payment_obj = client.payment.fetch(razorpay_payment_id)
                if payment_obj.get("status") != "captured":
                    return Response(
                        {"error": "Payment not captured", "status": payment_obj.get("status")},
                        status=400,
                    )

                order_obj = client.order.fetch(razorpay_order_id)
                order_notes = order_obj.get("notes", {})
            
                if str(order_notes.get("user_id")) != str(user.id) or str(order_notes.get("plan_id")) != str(plan.id):
                    return Response({"error": "Order does not belong to this user/plan"}, status=403)

                # ✅ Create or fetch purchase
                purchase, created = PlanPurchase.objects.get_or_create(
                    user=user,
                    plan=plan,
                    payment_id=razorpay_payment_id,
                    defaults={"order_id": razorpay_order_id, "is_successful": True},
                )

                if not created and purchase.is_successful:
                    return Response({"error": "Payment already processed"}, status=400)

                purchase.is_successful = True
                purchase.save(update_fields=["is_successful", "updated_at"])

                # ✅ Credit wallet safely via model method
                wallet, _ = Wallet.objects.select_for_update().get_or_create(user=user)
                wallet.credit_from_purchase(purchase)

                # ✅ Log + activity
                store_activity(
                    request,
                    "Recharged Wallet",
                    user,
                    {"message": f"Recharged Wallet with plan {plan.name}"},
                    200,
                    True,
                    "",
                )

                html_message = render_to_string("emails/wallet_recharge_success.html", {
                    "first_name": user.first_name,
                    "plan": plan,
                    "wallet": wallet,
                    "app_name": "Note AI",
                })
                plain_message = strip_tags(html_message)

            

                # ✅ Send email AFTER commit
                transaction.on_commit(
                    lambda: send_mail(        
                        subject="✅ Wallet Recharge Successful",
                        message=plain_message,
                        from_email="noreply@yourdomain.com",
                        recipient_list=[user.email],
                        html_message=html_message,
                        fail_silently=False,
                    )
                )

            return Response({"success": True}, status=200)

        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.error("AssignPlanView error", exc_info=True)
            return Response({"error": "Something went wrong, please contact support"}, status=500)