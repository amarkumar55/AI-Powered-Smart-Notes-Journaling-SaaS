from rest_framework import serializers
from .models import Plan, UserTransaction
from apis.api_auth.serializers import UserPublicSerializer

class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = ['name', 'description', 'slug', 'price', 'tokens', 'is_active']
        read_only_fields = ['slug', 'is_active']  # Only admins can toggle is_active

class UserTransactionSerializer(serializers.ModelSerializer):
    user = UserPublicSerializer(read_only=True)

    plan_name = serializers.CharField(source='plan.name', read_only=True)

    class Meta:
        model = UserTransaction
    
        fields = [
            'id', 
            'user',
            'transaction_id',
            'plan_name', 
            'payment_method', 
            'amount', 
            'currency',
            'status', 
            'transaction_date'
        ]

        read_only_fields = fields