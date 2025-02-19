from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SellerViewSet,
    SellerOrderViewSet,
    ProductsViewSet,
    CategoryViewSet,
    ReviewViewSet,
)

router = DefaultRouter()
router.register(r'sellers', SellerViewSet, basename='sellers')
router.register(r'seller-orders', SellerOrderViewSet, basename='seller-orders')
router.register(r'products', ProductsViewSet, basename='products')
router.register(r'categories', CategoryViewSet, basename='categories')

urlpatterns = [
    path("", include(router.urls)),
    path("products/<int:product_pk>/reviews/", ReviewViewSet.as_view({"get": "list", "post": "create"}), name="product-reviews"),
    path("products/<int:product_pk>/reviews/<int:pk>/", ReviewViewSet.as_view({"get": "retrieve", "put": "update", "patch": "partial_update", "delete": "destroy"}), name="review-detail"),
]
