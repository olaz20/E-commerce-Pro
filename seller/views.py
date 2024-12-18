from rest_framework import viewsets
from .models import Seller
from seller.serializers import *
from rest_framework.permissions import IsAuthenticated
from store.models import *
from api.serializers import OrderSerializer
from api.views import *
from rest_framework.exceptions import NotFound
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
            store_user = StoreUser.objects.get(id=user.id, user_type='seller')
        except StoreUser.DoesNotExist:
            raise NotFound("Seller profile not found for the current user.")
        
        # Step 2: Get all the products created by the seller
        seller_products = Product.objects.filter(seller=user)

        # Step 3: Get all order items associated with the seller's products
        order_items = OrderItem.objects.filter(product__in=seller_products)
        
        # Step 4: Get all orders that contain these order items
        orders = Order.objects.filter(order_items__in=order_items).distinct()

        return orders
    @action(detail=True, methods=['patch'], url_path='update-status')
    def update_status(self, request, pk=None):
        order = self.get_object()
        
        try:
            store_user = StoreUser.objects.get(id=user.id, user_type='seller')
        except StoreUser.DoesNotExist:
            raise NotFound("Seller profile not found for the current user.")
        
        order_status = request.data.get('order_status')
        payment_status = request.data.get('payment_status')

        # Validate order and payment statuses
        valid_order_statuses = [choice[0] for choice in Order.ORDER_STATUS_CHOICES]
        valid_payment_statuses = [choice[0] for choice in Order.PAYMENT_STATUS_CHOICES]

        if order_status and order_status not in valid_order_statuses:
            return Response({"order_status": "Invalid order status."}, status=status.HTTP_400_BAD_REQUEST)
        if payment_status and payment_status not in valid_payment_statuses:
            return Response({"payment_status": "Invalid payment status."}, status=status.HTTP_400_BAD_REQUEST)

        # Update the order
        if order_status:
            order.order_status = order_status
        if payment_status:
            order.payment_status = payment_status

        order.save()

        return Response({
            "message": "Order updated successfully.",
            "order": OrderSerializer(order).data
        }, status=status.HTTP_200_OK)