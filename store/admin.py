from django.contrib import admin
from .models import (
    Cart, CartItem, Country, State, LocalGovernment, ShippingFee,
    Address, Order, OrderItem, Wishlist
)


@admin.register(Cart)
class CartAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'session_id')
    search_fields = ('user__username', 'session_id')


@admin.register(CartItem)
class CartItemAdmin(admin.ModelAdmin):
    list_display = ('cart', 'product', 'quantity')
    search_fields = ('cart__user__username', 'product__name')


@admin.register(Country)
class CountryAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)


@admin.register(State)
class StateAdmin(admin.ModelAdmin):
    list_display = ('name', 'country')
    search_fields = ('name', 'country__name')


@admin.register(LocalGovernment)
class LocalGovernmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'state')
    search_fields = ('name', 'state__name')


@admin.register(ShippingFee)
class ShippingFeeAdmin(admin.ModelAdmin):
    list_display = ('lga', 'fee')
    search_fields = ('lga__name',)


@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'user', 'phone_number', 'street_address')
    search_fields = ('full_name', 'user__username', 'phone_number', 'street_address')


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner', 'order_status', 'payment_status', 'placed_at')
    search_fields = ('owner__username', 'tx_ref')
    list_filter = ('order_status', 'payment_status', 'placed_at')


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ('order', 'product', 'quantity', 'delivery_status')
    search_fields = ('order__owner__username', 'product__name')
    list_filter = ('delivery_status',)


@admin.register(Wishlist)
class WishlistAdmin(admin.ModelAdmin):
    list_display = ('user', 'session_id')
    search_fields = ('user__username', 'session_id')
