from django.contrib import admin

from .models import Cart, CartItem, Category, Product, Profile, Review


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("title", "category_id", "slug")
    prepopulated_fields = {"slug": ("title",)}


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ("name", "id", "price", "category")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(Cart)
class CartAdmin(admin.ModelAdmin):
    list_display = ("id", "created")


@admin.register(CartItem)
class CartItemAdmin(admin.ModelAdmin):
    list_display = ("id", "cart", "product", "quantity")


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ("product", "user", "rating", "date_posted")
    list_filter = ("product", "rating")  # Allows filtering by product and rating
    search_fields = (
        "user",
        "review",
    )  # Allows searching by reviewer name and review text


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "bio", "picture")
