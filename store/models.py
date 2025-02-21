import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from seller.models import Product
from services import Audit


class Cart(Audit):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True
    )
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    session_id = models.CharField(max_length=40, null=True, blank=True, unique=True)

    def merge_with(self, other_cart):
        for item in other_cart.items.all():
            existing_item = self.items.filter(product=item.product).first()
            if existing_item:
                existing_item.quantity += item.quantity
                existing_item.save()
            else:
                item.cart = self
                item.save()
        other_cart.delete()

    def __str__(self):
        return f"Cart for {self.user or self.session_id}"


class CartItem(Audit):
    cart = models.ForeignKey(
        Cart, on_delete=models.CASCADE, related_name="items", null=True, blank=True
    )
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="cartitems",
    )
    quantity = models.PositiveSmallIntegerField(default=1)


class Country(Audit):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class State(Audit):
    country = models.ForeignKey(
        Country, related_name="states", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class LocalGovernment(Audit):
    state = models.ForeignKey(
        State, related_name="local_governments", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class ShippingFee(Audit):
    lga = models.OneToOneField(
        LocalGovernment, on_delete=models.CASCADE, related_name="shipping_fee"
    )
    fee = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"Shipping Fee for {self.lga.name}: {self.fee}"


class Address(Audit):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="addresses"
    )
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15)
    country = models.ForeignKey(Country, on_delete=models.CASCADE)
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    local_government = models.ForeignKey(LocalGovernment, on_delete=models.CASCADE)
    street_address = models.CharField(max_length=255)
    landmark = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"{self.full_name} - {self.street_address}"


class Order(Audit):
    PAYMENT_STATUS_PENDING = "P"
    PAYMENT_STATUS_COMPLETE = "C"
    PAYMENT_STATUS_FAILED = "F"
    PAYMENT_STATUS_CHOICES = [
        (PAYMENT_STATUS_PENDING, "Pending"),
        (PAYMENT_STATUS_COMPLETE, "Complete"),
        (PAYMENT_STATUS_FAILED, "Failed"),
    ]

    ORDER_STATUS_CHOICES = [
        ("P", "Pending"),
        ("S", "Shipped"),
        ("D", "Delivered"),
        ("C", "Cancelled"),
    ]

    PAYMENT_METHOD_CHOICES = (
        ("flutterwave", "Flutterwave"),
        ("pay_on_delivery", "Pay on Delivery"),
    )

    payment_method = models.CharField(
        max_length=100, choices=PAYMENT_METHOD_CHOICES, default="pay_on_delivery"
    )
    shipping_address = models.ForeignKey(
        Address, on_delete=models.CASCADE, null=False, blank=False
    )
    order_status = models.CharField(
        max_length=1, choices=ORDER_STATUS_CHOICES, default="P"
    )
    placed_at = models.DateTimeField(auto_now_add=True)
    payment_status = models.CharField(
        max_length=50, choices=PAYMENT_STATUS_CHOICES, default=PAYMENT_STATUS_PENDING
    )
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    tx_ref = models.CharField(max_length=100, null=True, blank=True)
    items = models.ManyToManyField("OrderItem", related_name="orders")

    def __str__(self):
        return self.payment_status

    def clean(self):
        # Check if shipping_address _idis set
        if not self.shipping_address:  # checking the foreign key ID directly
            raise ValidationError(
                "Shipping address must be provided before processing the order."
            )

        # Check if payment_method is valid
        if not self.payment_method or self.payment_method not in dict(
            self.PAYMENT_METHOD_CHOICES
        ):
            raise ValidationError("A valid payment method must be provided.")

        # Additional checks for tx_ref and payment_status
        if self.tx_ref and self.payment_status == self.PAYMENT_STATUS_PENDING:
            raise ValidationError(
                "Transaction reference cannot be set for pending payments."
            )

    def save(self, *args, **kwargs):
        # Run the clean method before saving to ensure all fields are validated
        self.clean()

        # Check if the order is being updated and payment_status change is invalid
        if self.pk:  # Only validate on updates
            original = Order.objects.get(pk=self.pk)
            if (
                original.payment_status == self.PAYMENT_STATUS_COMPLETE
                and self.payment_status != self.PAYMENT_STATUS_COMPLETE
            ):
                raise ValueError("Cannot change a completed payment to another status.")

        # If validation passes, save the instance
        super().save(*args, **kwargs)

    @property
    def total_price(self):
        # Calculate total price from items related to the order (assuming items is related name)
        total = sum(
            item.quantity * item.product.price for item in self.order_items.all()
        )
        return total

    class Meta:
        indexes = [
            models.Index(fields=["tx_ref"]),
            models.Index(fields=["owner"]),
        ]


class OrderItem(Audit):
    order = models.ForeignKey(
        Order, on_delete=models.PROTECT, related_name="order_items"
    )
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    quantity = models.PositiveSmallIntegerField()
    delivery_status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "Pending"),
            ("processing", "Processing"),
            ("delivered", "Delivered"),
        ],
        default="pending",
    )

    @property
    def total_price(self):
        return self.quantity * self.product.price


class Wishlist(Audit):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, blank=True, null=True
    )  # Optional for anonymous users
    session_id = models.CharField(
        max_length=255, blank=True, null=True, unique=True
    )  # For anonymous users
    products = models.ManyToManyField(Product)

    def __str__(self):
        return f"Wishlist for {'User: ' + self.user.username if self.user else 'Session: ' + self.session_id}"
