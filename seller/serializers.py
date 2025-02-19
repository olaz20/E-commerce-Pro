from django.contrib.auth import get_user_model
from rest_framework import serializers

from store.models import Order, OrderItem

from .models import Category, Product, Review, Seller

User = get_user_model()


# Seller Serializer
class SellerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Seller
        fields = ["id", "user", "shop_name"]


# Order Item Serializer
class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ["id", "product", "quantity"]


# Order Serializer
class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)  # Orders have items
    shipping_address = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = ["id", "placed_at", "payment_status", "items", "shipping_address"]

    def get_shipping_address(self, obj):
        if hasattr(obj, "shipping_address") and obj.shipping_address:
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
        fields = ["id", "shop_name", "orders"]

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
    payment_status = serializers.ChoiceField(
        choices=Order.PAYMENT_STATUS_CHOICES, required=False
    )

    class Meta:
        model = Order
        fields = ["order_status", "payment_status"]

    def update(self, instance, validated_data):
        # Update only the fields that the seller can modify
        instance.order_status = validated_data.get(
            "order_status", instance.order_status
        )
        instance.payment_status = validated_data.get(
            "payment_status", instance.payment_status
        )
        instance.save()
        return instance


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ["category_id", "title", "slug"]


class ProductSerializer(serializers.ModelSerializer):
    category = CategorySerializer()  # Nested serializer for read/write
    avg_rating = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = [
            "id",
            "name",
            "price",
            "description",
            "category",
            "slug",
            "image",
            "inventory",
            "flash_sales",
            "top_deal",
            "avg_rating",
            "seller",
        ]

    def get_avg_rating(self, obj):
        # Access the dynamically annotated avg_rating or return None
        return getattr(obj, "avg_rating", None)

    def create(self, validated_data):
        # Pop out category data for handling separately
        category_data = validated_data.pop("category", None)

        # Get the logged-in user (the seller)
        user = self.context["request"].user  # This gives the logged-in user

        if category_data:
            # Ensure the category exists or is created
            category, created = Category.objects.get_or_create(**category_data)
            validated_data["category"] = category

        # Create the product instance, automatically associating the seller with the logged-in user
        product = Product.objects.create(seller=user, **validated_data)
        return product


class ReviewSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = Review
        fields = ["username", "review", "rating", "date_posted", "id"]

    def create(self, validated_data):
        product_id = self.context["product_id"]
        return Review.objects.create(product_id=product_id, **validated_data)
