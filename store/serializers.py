from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.db import transaction
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from seller.models import Product

from .models import (
    Address,
    Cart,
    CartItem,
    Country,
    LocalGovernment,
    Order,
    OrderItem,
    ShippingFee,
    State,
    Wishlist,
)

User = get_user_model()


class SimpleProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ["id", "name", "price"]


class CartItemSerializer(serializers.ModelSerializer):
    product = SimpleProductSerializer(many=False, read_only=True)
    item_total = serializers.SerializerMethodField(method_name="total")

    class Meta:
        model = CartItem
        fields = ["id", "product", "quantity", "item_total"]

    def total(self, cartitem: CartItem):
        return cartitem.quantity * cartitem.product.price if cartitem.product else 0


class AddCartItemSerializer(serializers.ModelSerializer):
    product_id = serializers.UUIDField()
    cart_id = serializers.UUIDField()
    quantity = serializers.IntegerField(min_value=1, required=True)

    class Meta:
        model = CartItem
        fields = ["cart_id", "product_id", "quantity"]

    def validate_cart_id(self, value):
        if not Cart.objects.filter(pk=value).exists():
            raise serializers.ValidationError(
                "There is no cart associated with the given id"
            )
        return value

    def validate_product_id(self, value):
        if not Product.objects.filter(pk=value).exists():
            raise serializers.ValidationError(
                "There is no product associated with the given id"
            )
        return value

    def save(self, **kwargs):
        cart_id = self.context["cart_id"]
        product_id = self.validated_data["product_id"]
        quantity = self.validated_data["quantity"]

        if not quantity:
            raise serializers.ValidationError({"quantity": "This field is required."})

        # Check if the Cart exists
        if not Cart.objects.filter(pk=cart_id).exists():
            raise serializers.ValidationError("The specified cart does not exist.")

        # Try to get the CartItem, if it exists, increment the quantity
        cartitem, created = CartItem.objects.get_or_create(
            cart_id=cart_id, product_id=product_id, defaults={"quantity": quantity}
        )
        cartitem.save()
        if not created:  # If the cart item already exists
            cartitem.quantity += quantity
            cartitem.save()

        self.instance = cartitem
        return self.instance


class UpdateCartItemSerializer(serializers.ModelSerializer):
    quantity = serializers.IntegerField(required=True, min_value=1)

    class Meta:
        model = CartItem
        fields = ["id", "quantity"]  

    def update(self, instance, validated_data):
        """
        Update an existing cart item with new values.
        """

        instance.quantity = validated_data.get("quantity", instance.quantity)
        instance.save()
        return instance


class CartItemDeleteSerializer(serializers.Serializer):
    product_id = serializers.UUIDField(write_only=True, required=True)

    def validate_product_id(self, value):
        """
        Ensure the product exists in the cart before deletion.
        """
        if not CartItem.objects.filter(product_id=value).exists():
            raise ValidationError("Product not found in the cart.")
        return value

    def delete_item(self, cart, product_id):
        """Handles the deletion of a product from the cart."""
        cart_item = CartItem.objects.filter(cart=cart, product_id=product_id).first()

        if cart_item:
            cart_item.delete()  # Delete the cart item
            return cart_item  # Return the deleted cart item (optional)
        else:
            raise ValidationError("Product not found in the cart.")


class CartSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    items = serializers.SerializerMethodField(method_name="get_items")
    grand_total = serializers.SerializerMethodField(method_name="main_total")
    user = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), required=False
    )

    class Meta:
        model = Cart
        fields = ["id", "user", "items", "session_id", "grand_total"]

    def get_items(self, cart):
        return [
            {"id": item.product.id, "name": item.product.name}
            for item in cart.items.all()
        ]

    def main_total(self, cart: Cart):
        items = cart.items.all()
        total = sum(
            item.quantity * item.product.price for item in items if item.product
        )
        return total


class WishlistSerializer(serializers.ModelSerializer):
    products = SimpleProductSerializer(many=True)
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = Wishlist
        fields = ["id", "username", "products", "session_id", "created_at"]


class WishlistCreateSerializer(serializers.ModelSerializer):
    product_id = serializers.ListField(
        child=serializers.UUIDField(), allow_empty=False, required=True, write_only=True
    )

    class Meta:
        model = Wishlist
        fields = ["product_id"]

    def validate_product_id(self, value):
        if not value:
            raise serializers.ValidationError("Product ID list cannot be empty.")
        # Check if all products exist
        if not Product.objects.filter(id__in=value).exists():
            raise serializers.ValidationError("One or more product IDs are invalid.")
        return value


class LocalGovernmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = LocalGovernment
        fields = ["id", "name"]


class StateSerializer(serializers.ModelSerializer):
    lgas = LocalGovernmentSerializer(many=True, read_only=True)

    class Meta:
        model = State
        fields = ["id", "name", "lgas"]


class CountrySerializer(serializers.ModelSerializer):
    states = StateSerializer(many=True, read_only=True)

    class Meta:
        model = Country
        fields = ["id", "name", "states"]


class ShippingFeeSerializer(serializers.ModelSerializer):
    lga = LocalGovernmentSerializer()

    class Meta:
        model = ShippingFee
        fields = ["lga", "fee"]


class AddressSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    country = serializers.CharField()
    state = serializers.CharField()
    local_government = serializers.CharField()

    class Meta:
        model = Address
        fields = [
            "id",
            "full_name",
            "phone_number",
            "country",
            "state",
            "local_government",
            "street_address",
            "landmark",
        ]

    def validate(self, data):
        # Convert country name to object
        try:
            country_obj = Country.objects.get(name=data["country"])
        except Country.DoesNotExist:
            raise serializers.ValidationError({"country": "Invalid country name."})

        # Convert state name to object
        try:
            state_obj = State.objects.get(name=data["state"], country=country_obj)
        except State.DoesNotExist:
            raise serializers.ValidationError(
                {"state": "Invalid state for the given country."}
            )

        # Convert local government name to object
        try:
            local_government_obj = LocalGovernment.objects.get(
                name=data["local_government"], state=state_obj
            )
        except LocalGovernment.DoesNotExist:
            raise serializers.ValidationError(
                {"local_government": "Invalid local government for the given state."}
            )

        # Replace string values with actual objects
        data["country"] = country_obj
        data["state"] = state_obj
        data["local_government"] = local_government_obj
        return data


class OrderItemSerializer(serializers.ModelSerializer):
    product = SimpleProductSerializer()

    class Meta:
        model = OrderItem
        fields = ["id", "product", "quantity"]


class OrderSerializer(serializers.ModelSerializer):
    payment_status = serializers.ChoiceField(
        choices=Order.PAYMENT_STATUS_CHOICES
    )  # Correct field name
    shipping_address = AddressSerializer()
    order_items = OrderItemSerializer(many=True, read_only=True)
    order_status = serializers.ChoiceField(choices=Order.ORDER_STATUS_CHOICES)

    class Meta:
        model = Order
        fields = [
            "id",
            "placed_at",
            "payment_status",
            "owner",
            "shipping_address",
            "payment_method",
            "order_items",
            "order_status",
        ]

    def get_item_names(self, obj):
        return [item.product.name for item in obj.items.all()]

    def validate(self, data):
        """
        Ensure all required fields are provided.
        """
        if not data.get("shipping_address"):
            raise serializers.ValidationError("Shipping address is required.")
        if not data.get("payment_method"):
            raise serializers.ValidationError("Payment method is required.")
        return data

    def create(self, validated_data):
        # Get the shipping address directly by ID
        shipping_address = validated_data.get("shipping_address")
        cart = validated_data.get("cart")

        if not cart:
            raise serializers.ValidationError("Cart is required to create an order.")

        total_amount = sum(
            item.product.price * item.quantity for item in cart.items.all()
        )

        # Create the order
        order = Order.objects.create(
            cart=cart,
            user=cart.user,  # Assuming cart has a user associated
            shipping_address=shipping_address,
            total_amount=total_amount,
            payment_status=validated_data.get("payment_status", "P"),
            payment_method=validated_data.get("payment_method"),
        )

        # Create order items for each cart item
        for item in cart.items.all():
            OrderItem.objects.create(
                order=order, product=item.product, quantity=item.quantity
            )

        cart.items.clear()  # Clear cart after order is placed
        return order


class CreateOrderSerializer(serializers.Serializer):
    cart_id = serializers.UUIDField()
    shipping_address_id = serializers.IntegerField()  #  it's a ForeignKey
    payment_method = serializers.ChoiceField(choices=Order.PAYMENT_METHOD_CHOICES)

    def validate_shipping_address_id(self, shipping_address_id):
        if not Address.objects.filter(id=shipping_address_id).exists():
            raise serializers.ValidationError("Invalid shipping address.")
        return shipping_address_id

    def validate_cart_id(self, cart_id):
        if not Cart.objects.filter(id=cart_id).exists():
            raise serializers.ValidationError("This cart_id is invalid.")
        return cart_id

    def save(self, **kwargs):
        with transaction.atomic():
            cart_id = self.validated_data["cart_id"]
            user_id = self.context["user_id"]
            shipping_address_id = self.validated_data["shipping_address_id"]
            payment_method = self.validated_data["payment_method"]
            cart_items = CartItem.objects.filter(cart_id=cart_id)

            for item in cart_items:
                if item.product.inventory < item.quantity:
                    raise serializers.ValidationError(
                        f"Not enough inventory for product '{item.product.name}'. "
                        f"Available: {item.product.inventory}, Requested: {item.quantity}."
                    )
            try:
                shipping_address = Address.objects.get(pk=shipping_address_id)
            except Address.DoesNotExist:
                raise serializers.ValidationError("Invalid shipping address.")

            order = Order.objects.create(
                owner_id=user_id,
                shipping_address=shipping_address,
                payment_method=payment_method,
            )
            # Create the order with the shipping address
            order_items = []
            for item in cart_items:
                item.product.inventory -= item.quantity
                item.product.save()
                order_items.append(
                    OrderItem(order=order, product=item.product, quantity=item.quantity)
                )
            OrderItem.objects.bulk_create(order_items)

            # Clean up Cart
            cart_items.delete()

            return order


class UpdateOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ["payment_choice"]
