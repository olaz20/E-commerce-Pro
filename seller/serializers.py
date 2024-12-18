
from rest_framework import serializers
from .models import Seller
from store.models import *
from api.serializers import OrderSerializer
from rest_framework.decorators import action
from rest_framework import status
from rest_framework.response import Response

# Seller Serializer
class SellerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Seller
        fields = ['id', 'user', 'shop_name']


# Order Item Serializer
class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ['id', 'product', 'quantity']


# Order Serializer
class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)  # Orders have items
    shipping_address = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = ['id', 'placed_at', 'payment_status', 'items', 'shipping_address']

    def get_shipping_address(self, obj):
        # Assuming Order has a foreign key to Address
        if hasattr(obj, 'shipping_address') and obj.shipping_address:
            return {
                "id": obj.shipping_address.id,
                "full_name": obj.shipping_address.full_name,
                "phone_number": obj.shipping_address.phone_number,
                "country": obj.shipping_address.country,
                "state": obj.shipping_address.state,
                "local_government": obj.shipping_address.local_government,
                "street_address": obj.shipping_address.street_address,
                "landmark": obj.shipping_address.landmark,
            }
        return None


# Seller Order Serializer
class SellerOrderSerializer(serializers.ModelSerializer):
    orders = serializers.SerializerMethodField()

    class Meta:
        model = Seller
        fields = ['id', 'shop_name', 'orders']

    def get_orders(self, obj):
        """
        Fetch all orders related to the seller's products.
        """
        # Step 1: Get all products by the seller
        seller_products = Product.objects.filter(seller=obj)

        # Step 2: Get all orders containing these products
        orders = Order.objects.filter(items__product__in=seller_products).distinct()

        # Step 3: Serialize these orders
        return OrderSerializer(orders, many=True).data
    
    
class OrderStatusUpdateSerializer(serializers.ModelSerializer):
    order_status = serializers.ChoiceField(choices=Order.ORDER_STATUS_CHOICES)
    payment_status = serializers.ChoiceField(choices=Order.PAYMENT_STATUS_CHOICES, required=False)

    class Meta:
        model = Order
        fields = ['order_status', 'payment_status']

    def update(self, instance, validated_data):
        # Update only the fields that the seller can modify
        instance.order_status = validated_data.get('order_status', instance.order_status)
        instance.payment_status = validated_data.get('payment_status', instance.payment_status)
        instance.save()
        return instance