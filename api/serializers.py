from store.models import *
from django.db import transaction
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import User, Group
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import ValidationError

User = get_user_model()
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category 
        fields = ['category_id', 'title', 'slug']

class ProductSerializer(serializers.ModelSerializer):
    category = CategorySerializer()  # Nested serializer for read/write
    avg_rating = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ['id', 'name', 'price', 'description', 'category', 'slug', 'image', 'inventory', "flash_sales", 'top_deal', 'avg_rating']

    def get_avg_rating(self, obj):
        # Access the dynamically annotated avg_rating or return None
        return getattr(obj, 'avg_rating', None)

    def create(self, validated_data):
        category_data = validated_data.pop('category', None)
        
        if category_data:
            # Ensure the category exists or is created
            category, created = Category.objects.get_or_create(**category_data)
            validated_data['category'] = category

        # Create the product instance
        product = Product.objects.create(**validated_data)
        return product

class ReviewSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    class Meta:
        model = Review
        fields = ['username',"review", "rating", "date_posted", "id"]
    def create(self, validated_data):
        product_id = self.context["product_id"]
        return Review.objects.create(product_id = product_id,  **validated_data)


class SimpleProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ["id", "name", "price"]

class CartItemSerializer(serializers.ModelSerializer):
    product = SimpleProductSerializer(many=False, read_only=True)
    item_total = serializers.SerializerMethodField(method_name="total")

    class Meta:
        model = CartItem
        fields = ["id", "product", "quantity", "item_total"]

    def total(self, cartitem: CartItem):
        return cartitem.quantity * cartitem.product.price if cartitem.product else 0

class AddCartItemSerializer(serializers.ModelSerializer):
    product_id = serializers.UUIDField()
    cart_id = serializers.UUIDField()
    quantity = serializers.IntegerField(min_value=1, required=True)
    class Meta:
        model = CartItem
        fields = ["cart_id", "product_id", "quantity"]
    def validate_cart_id(self, value):
        if not Cart.objects.filter(pk=value).exists():
            raise serializers.ValidationError("There is no cart associated with the given id")
        return value
    def validate_product_id(self, value):
        if not Product.objects.filter(pk=value).exists():
            raise serializers.ValidationError("There is no product associated with the given id")
        return value
    
    def save(self, **kwargs):
        cart_id = self.context["cart_id"]
        product_id = self.validated_data["product_id"]
        quantity = self.validated_data["quantity"]


        if not quantity:
            raise serializers.ValidationError({"quantity": "This field is required."})

        # Check if the Cart exists
        if not Cart.objects.filter(pk=cart_id).exists():
            raise serializers.ValidationError("The specified cart does not exist.")

        # Try to get the CartItem, if it exists, increment the quantity
        cartitem, created = CartItem.objects.get_or_create(
            cart_id=cart_id,
            product_id=product_id,
            defaults={'quantity': quantity}
        )

        if not created:  # If the cart item already exists
            cartitem.quantity += quantity
            cartitem.save()

        self.instance = cartitem
        return self.instance

class UpdateCartItemSerializer(serializers.ModelSerializer):
    quantity = serializers.IntegerField(required=True, min_value=1)
    
    class Meta:
        model = CartItem
        fields = ['id', 'quantity']  # Include the fields you want to update
    
    def update(self, instance, validated_data):
        """
        Update an existing cart item with new values.
        """
        # Update the quantity or other fields if necessary
        instance.quantity = validated_data.get('quantity', instance.quantity)
        
        # Save the updated instance
        instance.save()
        return instance

class CartItemDeleteSerializer(serializers.Serializer):
    product_id = serializers.UUIDField(write_only=True, required=True)
    
    def validate_product_id(self, value):
        """
        Ensure the product exists in the cart before deletion.
        """
        if not CartItem.objects.filter(product_id=value).exists():
            raise ValidationError("Product not found in the cart.")
        return value

    def delete_item(self, cart, product_id):
        """Handles the deletion of a product from the cart."""
        # Find the cart item that matches the product ID
        cart_item = CartItem.objects.filter(cart=cart, product_id=product_id).first()
        
        if cart_item:
            cart_item.delete()  # Delete the cart item
            return cart_item  # Return the deleted cart item (optional)
        else:
            raise ValidationError("Product not found in the cart.")  
class CartSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    items = serializers.SerializerMethodField(method_name='get_items')
    grand_total = serializers.SerializerMethodField(method_name='main_total')

    class Meta:
        model = Cart
        fields = ["id", "items", "session_id" ,"grand_total"]
    def get_items(self, cart):
        # Simplify the item structure: only include item ID and name
        return [
            {"id": item.product.id, "name": item.product.name}
            for item in cart.items.all()
        ]
    def main_total(self, cart: Cart):
        items = cart.items.all()
        total = sum(item.quantity * item.product.price for item in items if item.product)
        return total
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ["id", "name", "bio", "picture"]
class ApproveSellerSerializer(serializers.ModelSerializer):
    """Serializer for approving a seller."""
    email = serializers.EmailField()
    username= serializers.CharField(read_only=True)
    id=serializers.UUIDField()
    class Meta:
        model = StoreUser
        fields = ['id','email','username', 'is_approved']
        read_only_fields = [ 'username']  # Ensure email cannot be modified
        extra_kwargs = {
            'is_approved': {'required': False},  # Prevent requiring this field in input
        }

    def update(self, instance, validated_data):
        """
        Custom update method to set `is_approved` to True.
        """
        instance.is_approved = True  # Force approval
        instance.save(update_fields=['is_approved'])  # Save only `is_approved`
        return instance

    def validate(self, data):
        """
        Ensure no invalid changes to `is_approved`.
        """
        # Check if `is_approved` is provided and enforce it to be True
        if 'is_approved' in data and data['is_approved'] is not True:
            raise serializers.ValidationError(
                {"is_approved": "Approval can only set the value to True."}
            )
        return data



class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    user_type = serializers.ChoiceField(choices=[('buyer', 'Buyer'), ('seller', 'Seller')], required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'confirm_password', 'user_type')

    def validate(self, attrs):
        # Check that password and confirm_password fields match
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({"email": "This email is already in use."})
        if User.objects.filter(username=attrs['username']).exists():
            raise serializers.ValidationError({"username": "This username is already taken."})
        return attrs
    def create(self, validated_data):
        user_type = validated_data.pop('user_type')  # Extract user_type
        password = validated_data.pop('password')
        comfirm_password = validated_data.pop('confirm_password', None)
        # Create user
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(password)
        user.save()
         # Assign user to the specified group
         
        if user_type == 'seller':
            seller_group, _ = Group.objects.get_or_create(name='Seller')
            user.groups.add(seller_group)
        elif user_type == 'buyer':
            buyer_group, _ = Group.objects.get_or_create(name='Buyer')
            user.groups.add(buyer_group)
        elif user.user_type == "admin":
            admin_group, _ = Group.objects.get_or_create(name='Admin')
            user.groups.add(admin_group)
        return User.objects.create_user(**validated_data)
         # Ensure we return the user instance here
class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']  
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(username=email, password=password)
        # Find the user by email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password")

        # Check the password
        if not user.check_password(password):
            raise serializers.ValidationError("Invalid email or password")

        # Ensure user is active
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")
        
        # Ensure the user is approved if they are a seller
        if user.groups.filter(name="Seller").exists() and not getattr(user, 'is_approved', False):
            raise serializers.ValidationError("Your seller account is not approved yet.")

        return user  # Return the User instance for further processing
    
class WishlistSerializer(serializers.ModelSerializer):
    products = ProductSerializer(many=True)
    username = serializers.CharField(source='user.username', read_only=True)
    class Meta:
        model = Wishlist
        fields = ['id','username', 'products', 'session_id', 'created_at']
        
class WishlistCreateSerializer(serializers.ModelSerializer):
    product_id = serializers.ListField(
        child=serializers.UUIDField(), allow_empty=False, required=True,
        write_only=True
    )
    class Meta:
        model = Wishlist
        fields = ['product_id']
    def validate_product_id(self, value):
        if not value:
            raise serializers.ValidationError("Product ID list cannot be empty.")
        # Check if all products exist
        if not Product.objects.filter(id__in=value).exists():
            raise serializers.ValidationError("One or more product IDs are invalid.")
        return value
class AuthCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    auth_code = serializers.CharField(max_length=6)
    class Meta:
        model = User
        fields = ["auth_code"]
        
class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False, read_only=True)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)
    
    class Meta:
        fields = ['password', 'token', 'uidb64',]

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    auth_code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8)
    class Meta:
        model = User
        fields = ['email', 'auth_code', 'new_password']
        
class OrderItemSerializer(serializers.ModelSerializer):
    product = SimpleProductSerializer()
    class Meta:
        model = OrderItem 
        fields = ["id", "product", "quantity"]
        


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    item_names = serializers.SerializerMethodField()
    payment_choice = serializers.ChoiceField(choices=Order.PAYMENT_STATUS_CHOICES, default='P')   
        
    class Meta:
        model = Order 
        fields = ['id', "placed_at", "payment_choice", "owner", "items", "item_names"]
    def get_item_names(self, obj):
        # Fetch item names from related order items
        return [item.product.name for item in obj.items.all()]

    
class CreateOrderSerializer(serializers.Serializer):
    cart_id = serializers.UUIDField()
    
    
    
    def validate_cart_id(self, cart_id):
        if not Cart.objects.filter(pk=cart_id).exists():
            raise serializers.ValidationError("This cart_id is invalid")
        
        elif not CartItem.objects.filter(cart_id=cart_id).exists():
            raise serializers.ValidationError("Sorry your cart is empty")
        
        return cart_id
    
    
    
    def save(self, **kwargs):
        with transaction.atomic():
            cart_id = self.validated_data["cart_id"]
            user_id = self.context["user_id"]
            cartitems = CartItem.objects.filter(cart_id=cart_id)
            for item in cartitems:
                if item.product.inventory < item.quantity:
                    raise serializers.ValidationError(
                        f"Not enough inventory for product '{item.product.name}'. "
                        f"Available: {item.product.inventory}, Requested: {item.quantity}."
                    )
            order = Order.objects.create(owner_id = user_id)
            
            orderitems = [] 
            item_names = []
            for item in cartitems:
                item.product.inventory -= item.quantity
                item.product.save()

                # Create order item
                orderitems.append(
                    OrderItem(order=order, product=item.product, quantity=item.quantity)
                )
                item_names.append(item.product.name)
            OrderItem.objects.bulk_create(orderitems)
            self._item_names = item_names
            # Cart.objects.filter(id=cart_id).delete()
            return order
    @property
    def item_names(self):
    # Expose item names as a public property
        return getattr(self, "_item_names", [])

class UpdateOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order 
        fields = ["payment_choice"]