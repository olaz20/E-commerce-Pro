from django.db import models
from django.utils.text import slugify
import uuid
import django
from  django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.utils import timezone
import random
from django.utils.timezone import now
from datetime import timedelta
from django.core.exceptions import ValidationError

class Category(models.Model):
    title = models.CharField(max_length=200)
    category_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, unique=True)
    slug = models.SlugField(null=True, blank=True)
    featured_product = models.OneToOneField("Product", blank=True, null=True, on_delete=models.CASCADE, related_name='featured_product', unique=True)

    def save(self, *args, **kwargs):
        if not self.slug:  # Only create a slug if it hasn't been set
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title

class Product(models.Model):
    seller = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='products' , null=True)  # Linking product to seller
    name = models.CharField(max_length=255)
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, unique=True)
    inventory = models.IntegerField(null=False, default=1)
    image = models.ImageField(upload_to='img', blank= True, null=True, default='')
    description = models.TextField()
    uploaded_time = models.DateTimeField(auto_now_add=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    slug = models.SlugField(null=True, blank=True)
    category = models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='products', to='store.category')
    top_deal = models.BooleanField(default=False)
    flash_sales = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        if not self.slug:  # Only create a slug if it hasn't been set
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name
    
class Review(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    date_posted = models.DateTimeField(auto_now_add=True)
    review = models.TextField(blank=True, default="")
    rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    #name = models.CharField(max_length=50)   # we will changer to user later
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    def __str__(self):
        return f"Review by {self.user.username} - {self.review[:30]}..."
       
class Cart(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    session_id = models.CharField(max_length=40, null=True, blank=True, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    
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

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items', null=True, blank=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, blank=True, null=True, related_name='cartitems')
    quantity = models.PositiveSmallIntegerField(default=1)
    added_at = models.DateTimeField( default=timezone.now)
    

class Country(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class State(models.Model):
    country = models.ForeignKey(Country, related_name='states', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class LocalGovernment(models.Model):
    state = models.ForeignKey(State, related_name='local_governments', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name
class ShippingFee(models.Model):
    lga = models.OneToOneField(LocalGovernment, on_delete=models.CASCADE, related_name="shipping_fee")
    fee = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"Shipping Fee for {self.lga.name}: {self.fee}"
class Address(models.Model):
    id = models.BigIntegerField(primary_key=True, auto_created=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='addresses')
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15)
    country = models.ForeignKey(Country, on_delete=models.CASCADE)
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    local_government = models.ForeignKey(LocalGovernment, on_delete=models.CASCADE)
    street_address = models.CharField(max_length=255)
    landmark = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.street_address}"


class Order(models.Model):
    PAYMENT_STATUS_PENDING = 'P'
    PAYMENT_STATUS_COMPLETE = 'C'
    PAYMENT_STATUS_FAILED = 'F'
    PAYMENT_STATUS_CHOICES = [
        (PAYMENT_STATUS_PENDING, 'Pending'),
        (PAYMENT_STATUS_COMPLETE, 'Complete'),
        (PAYMENT_STATUS_FAILED, 'Failed')
    ]
    
    ORDER_STATUS_CHOICES = [
        ('P', 'Pending'),
        ('S', 'Shipped'),
        ('D', 'Delivered'),
        ('C', 'Cancelled'),
    ]
    
    PAYMENT_METHOD_CHOICES = (
        ('flutterwave', 'Flutterwave'),
        ('pay_on_delivery', 'Pay on Delivery'),
    )
    
    payment_method = models.CharField(max_length=100, choices=PAYMENT_METHOD_CHOICES, default='pay_on_delivery')
    shipping_address = models.ForeignKey(Address, on_delete=models.CASCADE, null=False, blank=False)
    order_status = models.CharField(max_length=1, choices=ORDER_STATUS_CHOICES, default='P')
    placed_at = models.DateTimeField(auto_now_add=True)
    payment_status = models.CharField(max_length=50, choices=PAYMENT_STATUS_CHOICES, default=PAYMENT_STATUS_PENDING)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    tx_ref = models.CharField(max_length=100, null=True, blank=True)
    items = models.ManyToManyField('OrderItem', related_name='orders')
    def __str__(self):
        return self.payment_status

    def clean(self):
        # Check if shipping_address _idis set
        if not self.shipping_address:  # checking the foreign key ID directly
            raise ValidationError("Shipping address must be provided before processing the order.")
        

        # Check if payment_method is valid
        if not self.payment_method or self.payment_method not in dict(self.PAYMENT_METHOD_CHOICES):
            raise ValidationError("A valid payment method must be provided.")

        # Additional checks for tx_ref and payment_status
        if self.tx_ref and self.payment_status == self.PAYMENT_STATUS_PENDING:
            raise ValidationError("Transaction reference cannot be set for pending payments.")

    def save(self, *args, **kwargs):
        # Run the clean method before saving to ensure all fields are validated
        self.clean()

        # Check if the order is being updated and payment_status change is invalid
        if self.pk:  # Only validate on updates
            original = Order.objects.get(pk=self.pk)
            if original.payment_status == self.PAYMENT_STATUS_COMPLETE and self.payment_status != self.PAYMENT_STATUS_COMPLETE:
                raise ValueError("Cannot change a completed payment to another status.")
        
        # If validation passes, save the instance
        super().save(*args, **kwargs)

    @property
    def total_price(self):
        # Calculate total price from items related to the order (assuming items is related name)
        total = sum(item.quantity * item.product.price for item in self.items.all())
        return total

    class Meta:
        indexes = [
            models.Index(fields=['tx_ref']),
            models.Index(fields=['owner']),
        ]
class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.PROTECT, related_name = "order_items")
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    quantity = models.PositiveSmallIntegerField()
    delivery_status = models.CharField(
        max_length=20,
        choices=[('pending', 'Pending'), ('processing', 'Processing'), ('delivered', 'Delivered')],
        default='pending'
    )

    @property
    def total_price(self):
        # Total price for a single OrderItem (product price * quantity)
        return self.quantity * self.product.price
class Wishlist(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, blank=True, null=True)  # Optional for anonymous users
    session_id = models.CharField(max_length=255, blank=True, null=True, unique=True)  # For anonymous users
    products = models.ManyToManyField(Product)
    created_at = models.DateTimeField(auto_now_add=True)
  

    def __str__(self):
        return f"Wishlist for {'User: ' + self.user.username if self.user else 'Session: ' + self.session_id}"
    
class EmailVerification(models.Model):
    email = models.EmailField(unique=True)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def generate_code(self):
        self.code = str(random.randint(100000, 999999))  # Generate a 6-digit code

  
class PasswordResetOTP(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # Dynamically references the user model
        on_delete=models.CASCADE,
        related_name='password_reset_otps'
    )
    auth_code= models.CharField(max_length=6)  # For a 6-digit OTP
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(timedelta(minutes=15))  # Default expiration: 15 minutes
    
    is_used = models.BooleanField(default=False)  # Track if the OTP has been used

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'auth_code'], name='unique_user_otp')
        ]

    def is_valid(self):
        """Check if the OTP is still valid."""
        return now() <= self.expires_at and not self.is_used

    def __str__(self):
        return f"OTP for {self.user.email} - {self.auth_code}"
