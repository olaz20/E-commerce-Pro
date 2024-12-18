from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SellerViewSet, SellerOrderViewSet

router = DefaultRouter()
router.register(r'sellers', SellerViewSet)
router.register(r'seller-orders', SellerOrderViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
