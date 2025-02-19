from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import OrderViewSet, CartViewSet, CartItemViewSet

# Create a router and register the viewsets
router = DefaultRouter()
router.register(r'orders', OrderViewSet, basename='orders')
router.register(r'cart', CartViewSet, basename='cart')
router.register(r'cart-items', CartItemViewSet, basename='cart-items')

urlpatterns = [
    path('', include(router.urls)),
    path('orders/<int:pk>/pay/', OrderViewSet.as_view({'post': 'pay'}), name='order-pay'),
    path('orders/confirm_payment/', OrderViewSet.as_view({'post': 'confirm_payment'}), name='confirm-payment'),
    path('cart/get_or_create/', CartViewSet.as_view({'get': 'get_or_create_cart'}), name='get-or-create-cart'),
]
