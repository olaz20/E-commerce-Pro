from django_filters.rest_framework import FilterSet

from .models import Product, Review


class ProductFilter(FilterSet):
    class Meta:
        model = Product
        fields = {"category_id": ["exact"], "price": ["gt", "lt"]}


class ReviewFilter(FilterSet):
    class Meta:
        model = Review
        fields = {
            "rating": [
                "exact",
                "gte",
                "lte",
            ],  # Filter by exact rating, greater than or equal, and less than or equal
        }

