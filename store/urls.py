from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AddressFormView,
    CartItemViewSet,
    CartViewSet,
    CountryListView,
    LGAListView,
    OrderViewSet,
    ShippingFeeView,
    StateListView,
)

# Create a router and register the viewsets
router = DefaultRouter()
router.register(r"orders", OrderViewSet, basename="orders")
router.register(r"cart", CartViewSet, basename="cart")
router.register(r"cart-items", CartItemViewSet, basename="cart-items")
router.register(r"addresses", AddressFormView, basename="address")


urlpatterns = [
    path("", include(router.urls)),
    path(
        "orders/<int:pk>/pay/", OrderViewSet.as_view({"post": "pay"}), name="order-pay"
    ),
    path(
        "orders/confirm_payment/",
        OrderViewSet.as_view({"post": "confirm_payment"}),
        name="confirm-payment",
    ),
    path(
        "cart/get_or_create/",
        CartViewSet.as_view({"get": "get_or_create_cart"}),
        name="get-or-create-cart",
    ),
    path("countries/", CountryListView.as_view(), name="country-list"),
    path("states/<int:country_id>/", StateListView.as_view(), name="state-list"),
    path("lgas/<int:state_id>/", LGAListView.as_view(), name="lga-list"),
    path(
        "shipping-fees/<int:lga_id>/",
        ShippingFeeView.as_view(),
        name="shipping-fee-list",
    ),
]
