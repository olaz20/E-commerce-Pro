import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.text import slugify
from services import Audit


class Seller(Audit):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    shop_name = models.CharField(max_length=255)
    def __str__(self):
        return self.shop_name


class Category(Audit):
    title = models.CharField(max_length=200)
    category_id = models.UUIDField(
        default=uuid.uuid4, editable=False, primary_key=True, unique=True
    )
    slug = models.SlugField(null=True, blank=True)
    featured_product = models.OneToOneField(
        "Product",
        blank=True,
        null=True,
        on_delete=models.CASCADE,
        related_name="featured_product",
        unique=True,
    )

    def save(self, *args, **kwargs):
        if not self.slug:  # Only create a slug if it hasn't been set
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title


class Product(Audit):
    seller = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="products",
        null=True,
    )  # Linking product to seller
    name = models.CharField(max_length=255)
    id = models.UUIDField(
        default=uuid.uuid4, editable=False, primary_key=True, unique=True
    )
    inventory = models.IntegerField(null=False, default=1)
    image = models.ImageField(upload_to="img", blank=True, null=True, default="")
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    slug = models.SlugField(null=True, blank=True)
    category = models.ForeignKey(
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="products",
        to="seller.category",
    )
    top_deal = models.BooleanField(default=False)
    flash_sales = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.slug:  # Only create a slug if it hasn't been set
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Review(Audit):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    date_posted = models.DateTimeField(auto_now_add=True)
    review = models.TextField(blank=True, default="")
    rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True
    )

    def __str__(self):
        return f"Review by {self.user.username} - {self.review[:30]}..."
