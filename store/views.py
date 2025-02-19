import uuid

import requests
from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.generics import ListAPIView
from rest_framework.mixins import (
    CreateModelMixin,
    DestroyModelMixin,
    ListModelMixin,
    RetrieveModelMixin,
)
from services import EmailService
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from services import CustomResponseRenderer
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from seller.models import Product
from seller.serializers import ProductSerializer
from services.permissions import IsAdmin, IsBuyer, IsOrderOwner, IsSeller
from store.serializers import (
    AddCartItemSerializer,
    AddressSerializer,
    CartItemSerializer,
    CartSerializer,
    CountrySerializer,
    CreateOrderSerializer,
    LocalGovernmentSerializer,
    OrderSerializer,
    ShippingFeeSerializer,
    StateSerializer,
    UpdateCartItemSerializer,
    UpdateOrderSerializer,
    WishlistCreateSerializer,
    WishlistSerializer,
)

from .models import (
    Address,
    Cart,
    CartItem,
    Country,
    LocalGovernment,
    Order,
    ShippingFee,
    State,
    Wishlist,
)
from services import CustomResponseMixin

def verify_payment(tx_ref):
    url = "https://api.flutterwave.com/v3/transactions/verify"
    headers = {"Authorization": f"Bearer {settings.FLW_SEC_KEY}"}
    try:
        # Send request to Flutterwave API
        response = requests.get(f"{url}/{tx_ref}", headers=headers)
        response.raise_for_status()  # Raise an error for HTTP codes 4xx/5xx
        return response.json()
    except requests.exceptions.RequestException as e:
        # Log the exception for debugging purposes
        print(f"Error verifying payment: {e}")
        return {"status": "error", "message": str(e), "data": None}


def initiate_payment(user, amount, email, order_id):
    # Validate inputs

    if not all([user, amount, email, order_id]):
        return Response({"error": "Invalid input parameters"}, status=400)

    url = "https://api.flutterwave.com/v3/payments"
    headers = {"Authorization": f"Bearer {settings.FLW_SEC_KEY}"}

    data = {
        "tx_ref": str(uuid.uuid4()),
        "amount": str(amount),
        "currency": "NGN",
        "redirect_url": "http:/127.0.0.1:8000/api/orders/confirm_payment/?o_id="
        + order_id,
        "meta": {
            "consumer_id": user.id,
        },
        "customer": {"email": email, "name": user.username or "Anonymous"},
        "customizations": {
            "title": "Olaz Buy",
        },
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        response_data = response.json()
        # Check if Flutterwave returned success
        if response.status_code == 200 and response_data.get("status") == "success":
            return Response(response_data, status=200)
        else:
            return Response(
                {"error": response_data.get("message", "Payment initiation failed")},
                status=400,
            )

    except requests.exceptions.RequestException as err:
        return Response({"error": f"Payment initiation error: {str(err)}"}, status=500)


class OrderViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, IsBuyer, IsOrderOwner]
    http_method_names = ["get", "patch", "post", "delete", "options", "head"]
    renderer_classes = [CustomResponseRenderer]
    email_service = EmailService()
    @action(detail=True, methods=["POST"])
    def pay(self, request, pk):
        order = self.get_object()
        order.PAYMENT_STATUS_CHOICES = Order.PAYMENT_STATUS_PENDING
        order.save()
        self.email_service.send_payment_email(request.user, order)
        return initiate_payment(request.user, order.total_price, request.user.email, str(order.id))

    @action(detail=False, methods=["POST"])
    def confirm_payment(self, request):
        order_id = request.GET.get("o_id")
        status = request.query_params.get("status")
        tx_ref = request.query_params.get("tx_ref")
        user = request.user
        try:
            # Use only valid fields from the Order model
            order = get_object_or_404(Order, id=order_id, owner=user)
        except Order.DoesNotExist:
            return Response(
                {"error": "Invalid order ID or unauthorized access"}, status=403
            )
        payment_verification = verify_payment(tx_ref)
        if payment_verification["status"] != "success":
            order.PAYMENT_STATUS_CHOICES = Order.PAYMENT_STATUS_FAILED
            return Response(
                {
                    "msg": "Payment verification failed",
                    "data": OrderSerializer(order).data,
                }
            )
        order.PAYMENT_STATUS_CHOICES = Order.PAYMENT_STATUS_COMPLETE
        order.save()
        self.email_service.send_payment_success_email(request.user, order)

        return Response({"msg": "Payment successful", "data": OrderSerializer(order).data})


    def get_permissions(self):
        if self.request.method in ["PATCH", "DELETE"]:
            return [IsAdmin(), IsSeller()]
        return [IsAuthenticated()]

    def create(self, request, *args, **kwargs):
        # Initialize serializer with user ID in the context
        serializer = CreateOrderSerializer(
            data=request.data, context={"user_id": request.user.id}
        )

        # Validate the serializer
        if serializer.is_valid(raise_exception=True):
            # Save the order with the specified payment status
            order = serializer.save(payment_status="P")
            self.email_service.send_order_confirmation_email(request.user, order)
            
            # Notify each seller involved in the order
        seller_notifications = {}
        for item in order.order_items.all():
            seller = (
                item.product.seller
            )  # each product has a 'seller' attribute
            if seller.email:  # Check if the seller has an email
                if seller.email not in seller_notifications:
                    seller_notifications[seller.email] = []
                seller_notifications[seller.email].append(item)
        print(seller_notifications)
        for seller_email, items in seller_notifications.items():
           self.email_service.send_seller_order_notification(seller_email, items) 
        response_serializer = OrderSerializer(order)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)
    def get_serializer_class(self):
        """
        Returns the appropriate serializer class based on the HTTP method.
        """
        if self.request.method == "POST":
            return CreateOrderSerializer
        elif self.request.method == "PATCH":
            return UpdateOrderSerializer
        return OrderSerializer

    def get_queryset(self):
        """
        Returns the queryset for authenticated users or an empty queryset for unauthenticated users.
        """
        user = self.request.user
        if not user.is_authenticated:
            return Order.objects.none()
        return Order.objects.filter(owner=user)


class CartViewSet(
    ListModelMixin,
    CreateModelMixin,
    RetrieveModelMixin,
    DestroyModelMixin,
    GenericViewSet,
):
    permission_classes = [AllowAny]
    queryset = Cart.objects.all()
    serializer_class = CartSerializer

    @action(detail=False, methods=["get"])
    def get_or_create_cart(self, request):
        user = request.user

        # If the user is authenticated and a Buyer
        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            # Retrieve or create a cart associated with the authenticated user
            cart, created = Cart.objects.get_or_create(user=user)
            if created:
                cart.save()
                print(f"Cart created for user: {user.id}")

            else:
                # For unauthenticated users, use the session cart
                session_id = request.session.session_key or request.session.create()
                cart, created = Cart.objects.get_or_create(session_id=session_id)
                if created:
                    cart.save()
            # Merge session cart into user cart if applicable
            if user.is_authenticated:
                session_cart = Cart.objects.filter(
                    session_id=request.session.session_key
                ).first()
                if session_cart and session_cart != cart:
                    for item in session_cart.items.all():
                        if not cart.items.filter(product=item.product).exists():
                            item.cart = cart
                            item.save()
                    session_cart.delete()
            # Return the cart items associated with the current cart
            return Response(CartItemSerializer(cart.items.all(), many=True).data)


class CartItemViewSet(ModelViewSet):
    permission_classes = [AllowAny]
    http_method_names = ["get", "post", "patch", "delete"]
    renderer_classes = [CustomResponseRenderer]
    def get_queryset(self):
        user = self.request.user

        # For authenticated users (buyers)
        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            cart, created = Cart.objects.get_or_create(user=user)
            if created:
                cart.save()

            # Check if there are items in the session cart that need to be moved to the user's cart
            session_id = (
                self.request.session.session_key or self.request.session.create()
            )
            session_cart = Cart.objects.filter(session_id=session_id).first()
            if session_cart:
                # Move items from session cart to user's cart
                for item in session_cart.items.all():
                    # Add the item to the user's cart if it's not already there
                    if not cart.items.filter(product=item.product).exists():
                        item.cart = cart
                        item.save()
                # Optionally, delete session cart after transfer
                session_cart.delete()

        else:
            # For unauthenticated users, use session cart
            session_id = (
                self.request.session.session_key or self.request.session.create()
            )
            cart, created = Cart.objects.get_or_create(session_id=session_id)
            cart.save()
        return CartItem.objects.filter(cart=cart)

    def get_serializer_class(self):
        if self.request.method == "POST":
            return AddCartItemSerializer
        elif self.request.method == "PATCH":
            return UpdateCartItemSerializer
        return CartItemSerializer

    def get_serializer_context(self):
        user = self.request.user

        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            # Get the user's cart, or handle if not found
            cart = Cart.objects.filter(user=user).first()
            if not cart:
                # Handle the case where no cart is found for the user
                cart = Cart.objects.create(user=user)  # Create a new cart if needed
        else:
            # Use the session-based cart
            session_id = (
                self.request.session.session_key or self.request.session.create()
            )
            cart = Cart.objects.filter(session_id=session_id).first()
            if not cart:
                # Handle the case where no cart is found for the session
                cart = Cart.objects.create(
                    session_id=session_id
                )  # Create a new cart if needed

        return {"cart_id": cart.id}

    def destroy(self, request, *args, **kwargs):
        user = self.request.user
        session_id = self.request.session.session_key or self.request.session.create()

        # Get the cart based on user authentication or session ID
        if user.is_authenticated:
            cart, created = Cart.objects.get_or_create(user=user)
        else:
            cart, created = Cart.objects.get_or_create(session_id=session_id)

        # Get the cart item by product_id (provided as pk in the URL)
        product_id = kwargs.get("pk")

        product = get_object_or_404(Product, id=product_id)

        # Try to find the cart item and delete it
        cart_item = CartItem.objects.filter(cart=cart, product=product).first()

        if cart_item:
            cart_item.delete()  # Delete the cart item
            return Response(
                {"message": "Product removed from cart."},
                status=status.HTTP_204_NO_CONTENT,
            )
        else:
            return Response(
                {"detail": "Product not found in the cart."},
                status=status.HTTP_404_NOT_FOUND,
            )


class WishListViewSet(ModelViewSet):
    permission_classes = [AllowAny]
    http_method_names = ["get", "post", "delete"]
    renderer_classes = [CustomResponseRenderer]
    def get_queryset(self):
        user = self.request.user
        session_id = self.request.session.session_key
        if not session_id:
            session_id = (
                self.request.session.create()
            )  # Generate a new session ID if it doesn't exist

        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            # Merge session wishlist into user wishlist
            wishlist, created = Wishlist.objects.get_or_create(user=user)
        else:
            # Return session wishlist for unauthenticated users
            wishlist, created = Wishlist.objects.get_or_create(session_id=session_id)
        return wishlist.products.all()

    def get_serializer_class(self):
        if self.request.method == "POST":
            return WishlistCreateSerializer
        else:
            return WishlistSerializer

    def get_serializer_context(self):
        """
        Provide additional context to the serializer.
        """
        user = self.request.user
        session_id = self.request.session.session_key
        if not session_id:
            session_id = (
                self.request.session.create()
            )  # Generate a new session ID if it doesn't exist

        if user.is_authenticated:
            wishlist, _ = Wishlist.objects.get_or_create(user=user)
        else:
            wishlist, _ = Wishlist.objects.get_or_create(session_id=session_id)
        return {"wishlist_id": wishlist.id}

    def list(self, request, *args, **kwargs):
        """List all products in the wishlist."""
        wishlist = self.get_queryset()  # Fetch products from get_queryset()
        serializer = ProductSerializer(wishlist, many=True)  # Serialize products
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """Add products to the wishlist."""
        user = self.request.user
        session_id = self.request.session.session_key or self.request.session.create()

        # Get wishlist based on user authentication
        if user.is_authenticated:
            wishlist, _ = Wishlist.objects.get_or_create(user=user)
        else:
            wishlist, _ = Wishlist.objects.get_or_create(session_id=session_id)

        serializer = WishlistCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        product_ids = serializer.validated_data["product_id"]
        products = Product.objects.filter(id__in=product_ids)

        wishlist.products.add(*products)
        return Response({"message": "Products added to wishlist successfully."})

    def destroy(self, request, *args, **kwargs):
        """Remove a product from the wishlist."""
        user = self.request.user
        session_id = self.request.session.session_key or self.request.session.create()

        # Get wishlist based on user authentication
        if user.is_authenticated:
            wishlist = Wishlist.objects.get(user=user)
        else:
            wishlist = Wishlist.objects.get(session_id=session_id)

        product_id = kwargs.get("pk")
        product = get_object_or_404(Product, id=product_id)

        # Remove product from the wishlist
        wishlist.products.remove(product)
        return Response({"message": "Product removed from wishlist."})


class AddressFormView(viewsets.ViewSet):
    """
    A viewset to manage the address for the authenticated user.
    """

    permission_classes = [IsAuthenticated, IsBuyer]
    renderer_classes = [CustomResponseRenderer]
    def get(self, request, *args, **kwargs):
        """
        Fetches all addresses for the authenticated user.
        If no addresses exist, return a message and an empty list.
        """
        # Retrieve all addresses for the authenticated user
        addresses = Address.objects.filter(user=request.user)

        if addresses.exists():
            # Serialize the addresses into a list of dictionaries
            address_data = [
                {
                    "id": address.id,
                    "full_name": address.full_name,
                    "phone_number": address.phone_number,
                    "country": address.country.name,
                    "state": address.state.name,
                    "local_government": address.local_government.name,
                    "street_address": address.street_address,
                    "landmark": address.landmark,
                }
                for address in addresses
            ]
            return Response(
                {
                    "message": "Addresses retrieved successfully",
                    "addresses": address_data,
                },
                status=status.HTTP_200_OK,
            )
        else:
            # No addresses found for the user
            return Response(
                {
                    "message": "No addresses found for the user",
                    "addresses": [],
                },
                status=status.HTTP_404_NOT_FOUND,
            )

    def create(self, request, *args, **kwargs):
        """
        Handles creating a new address.
        """
        # Extract data from the request
        address_data = request.data

        # Use a serializer to validate and save the address data
        serializer = AddressSerializer(data=address_data)
        if serializer.is_valid():
            # Save the address to the database
            address = serializer.save(user=self.request.user)
            return Response(
                {
                    "message": "Address created successfully",
                    "address": {
                        "full_name": serializer.data.get("full_name"),
                        "phone_number": serializer.data.get("phone_number"),
                        "country": address.country.name,
                        "state": address.state.name,
                        "local_government": address.local_government.name,
                        "street_address": serializer.data.get("street_address"),
                        "landmark": serializer.data.get("landmark"),
                    },
                },
                status=status.HTTP_201_CREATED,
            )
        else:
            # Return validation errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None, *args, **kwargs):
        """
        Handles partial update (PATCH) of an address.
        """
        try:
            # Retrieve the address object for the authenticated user
            address = Address.objects.get(pk=pk, user=request.user)
        except Address.DoesNotExist:
            return Response(
                {
                    "error": "Address not found or you do not have permission to modify it."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # Validate and update the address using the serializer
        serializer = AddressSerializer(address, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "message": "Address updated successfully",
                    "address": {
                        "full_name": serializer.data.get("full_name"),
                        "phone_number": serializer.data.get("phone_number"),
                        "country": address.country.name,
                        "state": address.state.name,
                        "local_government": address.local_government.name,
                        "street_address": serializer.data.get("street_address"),
                        "landmark": serializer.data.get("landmark"),
                    },
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        """
        Handles deleting an address.
        """
        try:
            # Retrieve the address object for the authenticated user
            address = Address.objects.get(pk=pk, user=request.user)
        except Address.DoesNotExist:
            return Response(
                {
                    "error": "Address not found or you do not have permission to delete it."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # Delete the address
        address.delete()
        return Response(
            {"message": "Address deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


class CountryListView(ListAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer
    renderer_classes = [CustomResponseRenderer]

class StateListView(ListAPIView):
    renderer_classes = [CustomResponseRenderer]
    def get_queryset(self):
        country_id = self.kwargs["country_id"]
        return State.objects.filter(country_id=country_id)

    serializer_class = StateSerializer


class LGAListView(ListAPIView):
    renderer_classes = [CustomResponseRenderer]
    def get_queryset(self):
        state_id = self.kwargs["state_id"]
        return LocalGovernment.objects.filter(state_id=state_id)

    serializer_class = LocalGovernmentSerializer


class ShippingFeeView(ListAPIView):
    renderer_classes = [CustomResponseRenderer]
    def get_queryset(self):
        lga_id = self.kwargs["lga_id"]
        return ShippingFee.objects.filter(lga_id=lga_id)

    serializer_class = ShippingFeeSerializer
