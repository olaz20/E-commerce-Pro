from api.serializers import OrderSerializer
from api.views import *
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated

from seller.serializers import *
from services.permissions import IsSeller
from store.models import *
from userauth.models import StoreUser

from .models import Seller


class SellerViewSet(viewsets.ModelViewSet):
    queryset = Seller.objects.all()
    serializer_class = SellerSerializer
    permission_classes = [IsAuthenticated, IsSeller]

    def get_queryset(self):
        # Filter sellers based on the logged-in user (seller)
        return Seller.objects.filter(user=self.request.user)


class SellerOrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()  # Define the queryset
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated, IsSeller]

    def get_queryset(self):
        user = self.request.user

        try:
            store_user = StoreUser.objects.get(id=user.id, user_type="seller")
        except StoreUser.DoesNotExist:
            raise NotFound("Seller profile not found for the current user.")

        # Step 2: Get all the products created by the seller
        seller_products = Product.objects.filter(seller=user)

        # Step 3: Get all order items associated with the seller's products
        order_items = OrderItem.objects.filter(product__in=seller_products)

        # Step 4: Get all orders that contain these order items
        orders = Order.objects.filter(order_items__in=order_items).distinct()

        return orders

    @action(detail=True, methods=["patch"], url_path="update-status")
    def update_status(self, request, pk=None):
        order = self.get_object()

        try:
            store_user = StoreUser.objects.get(id=user.id, user_type="seller")
        except StoreUser.DoesNotExist:
            raise NotFound("Seller profile not found for the current user.")

        order_status = request.data.get("order_status")
        payment_status = request.data.get("payment_status")

        # Validate order and payment statuses
        valid_order_statuses = [choice[0] for choice in Order.ORDER_STATUS_CHOICES]
        valid_payment_statuses = [choice[0] for choice in Order.PAYMENT_STATUS_CHOICES]

        if order_status and order_status not in valid_order_statuses:
            return Response(
                {"order_status": "Invalid order status."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if payment_status and payment_status not in valid_payment_statuses:
            return Response(
                {"payment_status": "Invalid payment status."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update the order
        if order_status:
            order.order_status = order_status
        if payment_status:
            order.payment_status = payment_status

        order.save()

        return Response(
            {
                "message": "Order updated successfully.",
                "order": OrderSerializer(order).data,
            },
            status=status.HTTP_200_OK,
        )


class ProductsViewSet(ModelViewSet):
    queryset = Product.objects.all().annotate(avg_rating=Avg("review__rating"))
    serializer_class = ProductSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ProductFilter
    search_fields = ["name", "description"]
    ordering_fields = ["price", "avg_rating"]
    pagination_class = PageNumberPagination

    def get_permissions(self):
        if self.action in ["create", "update", "partial_update", "destroy"]:
            self.permission_classes = [IsAuthenticated, IsSeller]
        else:
            self.permission_classes = [AllowAny]
        return super().get_permissions()


class CategoryViewSet(ModelViewSet):
    pagination_class = PageNumberPagination
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class ReviewViewSet(ModelViewSet):
    serializer_class = ReviewSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ReviewFilter
    search_fields = ["review"]  # Or other relevant fields
    ordering_fields = ["created_at"]
    pagination_class = PageNumberPagination

    def get_permissions(self):
        if self.action in ["create", "update", "partial_update", "destroy"]:
            self.permission_classes = [IsAuthenticated]
        else:
            self.permission_classes = [AllowAny]
        return super().get_permissions()

    def get_queryset(self):
        return Review.objects.filter(product_id=self.kwargs["product_pk"])

    def get_serializer_context(self):
        return {"product_id": self.kwargs["product_pk"]}

    def perform_create(self, serializer):
        product_id = self.kwargs["product_pk"]  # Get product ID from the URL

        # Check if the product exists
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response(
                {"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND
            )

        # Save the review with the valid product_id
        serializer.save(product=product, user=self.request.user)
