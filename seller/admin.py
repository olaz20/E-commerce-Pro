from django.contrib import admin

from .models import Category, Product, Review, Seller


@admin.register(Seller)
class SellerAdmin(admin.ModelAdmin):
    list_display = ("user", "shop_name")
    search_fields = ("shop_name", "user__username")


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("title", "category_id", "slug", "featured_product")
    search_fields = ("title", "slug")
    prepopulated_fields = {"slug": ("title",)}


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "seller",
        "price",
        "inventory",
        "category",
        "top_deal",
        "flash_sales",
    )
    list_filter = ("top_deal", "flash_sales", "category")
    search_fields = ("name", "seller__username", "category__title")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ("product", "user", "rating", "date_posted")
    list_filter = ("rating", "date_posted")
    search_fields = ("product__name", "user__username", "review")
