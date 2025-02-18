from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import SellerOrderViewSet, SellerViewSet

router = DefaultRouter()
router.register(r"sellers", SellerViewSet)
router.register(r"seller-orders", SellerOrderViewSet)

urlpatterns = [
    path("", include(router.urls)),
]
