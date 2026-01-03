from rest_framework import serializers
from apis.api_payment.models import Payment, Refund

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['id','amount','currency','status','order_id','payment_id','description','created_at']

class RefundSerializer(serializers.ModelSerializer):
    class Meta:
        model = Refund
        fields = ['id','amount','currency','status','order_id','refund_id','reason']

# ----------------------------
# Serializers for Validation
# ----------------------------
class PaymentProcessSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=1)
    payment_method = serializers.ChoiceField(choices=['card', 'upi', 'paypal'])  # adapt to your gateway
    description = serializers.CharField(required=False, allow_blank=True)
    currency = serializers.ChoiceField(choices=['INR'])  # restrict to supported currencies


class RefundRequestSerializer(serializers.Serializer):
    payment_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=1)

