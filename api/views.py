from django.shortcuts import  get_object_or_404
from rest_framework.decorators import action
from rest_framework import viewsets, exceptions
from rest_framework.viewsets import ModelViewSet
from rest_framework import status
from store.models import *
from .serializers import *
from django.contrib.auth.models import AnonymousUser
from .filter import *
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import Group
from django.contrib.auth.hashers import make_password
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny,  BasePermission, IsAuthenticatedOrReadOnly
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.mixins import CreateModelMixin, RetrieveModelMixin, DestroyModelMixin, ListModelMixin
from rest_framework.viewsets import GenericViewSet
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
from django.db.models import Avg
from .utils import *
from django.contrib.auth import logout
from store.models import EmailVerification
from django.contrib.auth import authenticate
from django.urls import reverse
from django.core.cache import cache
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from itsdangerous.url_safe import URLSafeTimedSerializer
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from django.http import HttpResponsePermanentRedirect
import os
from django.core.mail import send_mail, BadHeaderError
from django.utils.crypto import get_random_string
import requests
from rest_framework.permissions import IsAdminUser
from rest_framework.exceptions import NotFound
from api import serializers

# Create your views here.

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name="Admin").exists()


class IsSeller(BasePermission):
    def has_permission(self, request, view):
        # Check if the user is authenticated and belongs to the "Seller" group
        if request.user and request.user.is_authenticated:
            # Verify if the user is in the "Seller" group and is approved
            return (
                request.user.groups.filter(name="Seller").exists()
                and getattr(request.user, 'is_approved', False)
            )
        return False

class IsBuyer(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name="Buyer").exists()

class AdminViewSet(ModelViewSet):
    queryset = StoreUser.objects.all()
    permission_classes = [IsAuthenticated, IsAdminUser]

    serializer_class = ApproveSellerSerializer
    def get_queryset(self):
        """
        Return unapproved sellers for admin to manage.
        """
        return StoreUser.objects.filter(user_type='seller', is_approved=False)

    @action(detail=True, methods=['patch'], permission_classes=[IsAdminUser])
    def approve_seller(self, request, pk=None):
        """
        Approve a seller by email and update only the `is_approved` field.
        """
        seller = self.get_object()
        if seller.is_approved:
            return Response({'message': 'Seller is already approved.'}, status=200)

        if not seller.is_approved:   
            seller.is_approved = True
            seller.save(update_fields=['is_approved'])
        else:
             return Response({'error': 'No seller with this ID exists.'}, status=status.HTTP_404_NOT_FOUND)
                # Send approval email
        if seller.email:
            subject = "Your Seller Account Has Been Approved"
            message = f"""
                <html>
                    <body>
                        <h3>Dear {request.user.username},</h3>
                        <p>Your seller account has been successfully approved. You can now start listing your products on the platform.</p>
                        <p>Thank you for being part of our community.</p>
                    </body>
                </html>
            """
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [seller.email]

            try:
                send_mail(subject, '', from_email, recipient_list, html_message=message)
            except BadHeaderError:
                return Response({'error': 'Invalid header. Email could not be sent.'}, status=400)

        return Response({'message': 'Seller approved and email sent successfully.'}, status=200)

            




def initiate_payment(amount, email, order_id):
    url = "https://api.flutterwave.com/v3/payments"
    headers = {
        "Authorization": f"Bearer {settings.FLW_SEC_KEY}"
        
    }
    
    data = {
        "tx_ref": str(uuid.uuid4()),
        "amount": str(amount), 
        "currency": "NGN",
        "redirect_url": "http:/127.0.0.1:8000/api/orders/confirm_payment/?o_id=" + order_id,
        "meta": {
            "consumer_id": 23,
            "consumer_mac": "92a3-912ba-1192a"
        },
        "customer": {
            "email": email,
            "phonenumber": "080****4528",
            "name": "to be updated"
        },
        "customizations": {
            "title": "Pied Piper Payments",
            "logo": "http://www.piedpiper.com/app/themes/joystick-v27/images/logo.png"
        }
    }
    

    try:
        response = requests.post(url, headers=headers, json=data)
        response_data = response.json()
        return Response(response_data)
    
    except requests.exceptions.RequestException as err:
        print("the payment didn't go through")
        return Response({"error": str(err)}, status=500)
def verify_payment(tx_ref):
        url = "https://api.flutterwave.com/v3/transactions/verify"
        headers = {
            "Authorization": f"Bearer {settings.FLW_SEC_KEY}"
        }
        try:
            # Send request to Flutterwave API
            response = requests.get(f"{url}/{tx_ref}", headers=headers)
            response.raise_for_status()  # Raise an error for HTTP codes 4xx/5xx
            return response.json()
        except requests.exceptions.RequestException as e:
        # Log the exception for debugging purposes
            print(f"Error verifying payment: {e}")
            return {
                "status": "error",
                "message": str(e),
                "data": None
            } 
 
class OrderViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, IsBuyer]
    http_method_names = ["get", "patch", "post", "delete", "options", "head"]
    
    
    @action(detail=True, methods=['POST'])
    def pay(self, request, pk):
        order = self.get_object()
        order.PAYMENT_STATUS_CHOICES = "P"
        amount = order.total_price
        email = request.user.email
        order_id = str(order.id)
        subject = "Payment Initiated"
        message = f"""
        Hi {request.user.username},

        You’ve initiated a payment for your order. Here are the details:
        - Amount: #{amount}

        We’ll notify you once your payment is confirmed.

        Regards,
        OLAZ BUY
        """
        if request.user.email:
           send_plain_text_email(subject, message, [request.user.email])

        return initiate_payment(amount, email, order_id)
    
    @action(detail=False, methods=["POST"])
    def confirm_payment(self, request):
        order_id = request.GET.get("o_id")
        status = request.query_params.get("status")
        tx_ref = request.query_params.get("tx_ref")
        user = request.user
        try:
        # Use only valid fields from the Order model
           order = Order.objects.get(id=order_id, owner=user)
        except Order.DoesNotExist:
           return Response({"error": "Invalid order ID or unauthorized access"}, status=403)
        payment_verification = verify_payment(tx_ref)
        if payment_verification['status'] != 'success':
            order.PAYMENT_STATUS_CHOICES = "F"
            order.save()  # Save the failed status
            return Response({
                "msg": "Payment verification failed",
                "data": OrderSerializer(order).data
            })
        order.PAYMENT_STATUS_CHOICES = "C"
        order.save()
        serializer = OrderSerializer(order)
        item_names = ", ".join(serializer.data['item_names'])
        # Send plain-text payment confirmation email
        subject = "Payment Successful"
        message = f"""
        Hi {request.user.username},

        Your payment was successful! Here are the order details:
        - Item: {item_names}
        
        - Total Price: ${order.total_price}

        We’ll notify you when your order is shipped or delivered.

        Regards,
        OLAZ BUY
        """
        if request.user.email:
           send_plain_text_email(subject, message, [request.user.email])

        data = {
            "msg": "payment was successful",
            "data": serializer.data
        }
        return Response(data)
    
    
    def get_permissions(self):
        if self.request.method in ["PATCH", "DELETE"]:
            return [IsAdminUser()]
        return [IsAuthenticated()]
    
            
    
    
    def create(self, request, *args, **kwargs):
        serializer = CreateOrderSerializer(data=request.data, context={"user_id": self.request.user.id})
        serializer.is_valid(raise_exception=True)
        order = serializer.save(PAYMENT_STATUS_CHOICES='P')
        order = serializer.save()
        item_names = ", ".join(serializer.item_names)
        total_quantity = sum(item.quantity for item in order.items.all())
         # Send plain-text order confirmation email
        subject = "Order Confirmation"
        message = f"""
        Hi {request.user.username},

        Thank you for your order! Here are the details:
        - Item: {item_names}
        - Quantity: {total_quantity}
        - Total Price: ${order.total_price}

        We’ll notify you when your order is shipped.

        Regards,
        Olaz buy
        """
        if request.user.email:
            send_plain_text_email(subject, message, [request.user.email])

        serializer = OrderSerializer(order)
        return Response(serializer.data)
        
    

    
    
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateOrderSerializer
        elif self.request.method == 'PATCH':
            return UpdateOrderSerializer
        return OrderSerializer
       
    
    def get_queryset(self):
        user = self.request.user
        if isinstance(user, AnonymousUser):
            # Return an empty queryset if the user is anonymous (not authenticated)
            return Order.objects.none()
        return Order.objects.filter(owner=user)
        # def get_serializer_context(self):
        #     return {"user_id": self.request.user.id}
                
# Create your views here.

class ProductsViewSet(ModelViewSet):
    queryset = Product.objects.all().annotate(avg_rating=Avg('review__rating'))
    serializer_class = ProductSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ProductFilter
    search_fields = ['name', 'description']
    ordering_fields = ['price', 'avg_rating']
    pagination_class = PageNumberPagination
    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            self.permission_classes = [IsAuthenticated, IsSeller]
        else:
            self.permission_classes = [AllowAny]
        return super().get_permissions()

    # Example action for sellers to get order updates
    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated, IsSeller])
    def order_updates(self, request):
        # Logic for retrieving order updates
        pass
    parser_classes = (MultiPartParser, FormParser) # this will allow image upload

class CategoryViewSet(ModelViewSet):
    pagination_class = PageNumberPagination
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

class ReviewViewSet(ModelViewSet):
    serializer_class = ReviewSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ReviewFilter
    search_fields = ['review']  # Or other relevant fields
    ordering_fields = ['created_at']
    pagination_class = PageNumberPagination

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            self.permission_classes = [IsAuthenticated]
        else:
            self.permission_classes = [AllowAny]
        return super().get_permissions()
    
    def get_queryset(self):
        return Review.objects.filter(product_id=self.kwargs["product_pk"])

    def get_serializer_context(self):
        return {"product_id": self.kwargs["product_pk"]}

    def perform_create(self, serializer):
        product_id = self.kwargs['product_pk']  # Get product ID from the URL
        
        # Check if the product exists
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)

        # Save the review with the valid product_id
        serializer.save(product=product, user=self.request.user)

class CartViewSet(ListModelMixin,CreateModelMixin, RetrieveModelMixin, DestroyModelMixin,GenericViewSet):
    permission_classes = [AllowAny]
    queryset = Cart.objects.all()
    serializer_class = CartSerializer

class CartItemViewSet(ModelViewSet):
    permission_classes = [AllowAny]
    http_method_names = ["get", "post", "patch", "delete"]
    def get_queryset(self):
        user = self.request.user
        
        # For authenticated users (buyers)
        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            cart, created = Cart.objects.get_or_create(user=user)
            
            # Check if there are items in the session cart that need to be moved to the user's cart
            session_id = self.request.session.session_key or self.request.session.create()
            session_cart = Cart.objects.filter(session_id=session_id).first()
            if session_cart:
                # Move items from session cart to user's cart
                for item in session_cart.items.all():
                    # Add the item to the user's cart if it's not already there
                    if not cart.items.filter(product=item.product).exists():
                        item.cart = cart
                        item.save()
                # Optionally, delete session cart after transfer
                session_cart.delete()

        else:
            # For unauthenticated users, use session cart
            session_id = self.request.session.session_key or self.request.session.create()
            cart, created = Cart.objects.get_or_create(session_id=session_id)

        return CartItem.objects.filter(cart=cart)
    
    def get_serializer_class(self):
        if self.request.method == "POST":
            return AddCartItemSerializer
        elif self.request.method == 'PATCH':
            return UpdateCartItemSerializer
        return CartItemSerializer
        
    

    def get_serializer_context(self):
        user = self.request.user
        # Use user cart for authenticated buyers, else use session cart
        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            cart = Cart.objects.get(user=user)
        else:
            session_id = self.request.session.session_key or self.request.session.create()
            cart = Cart.objects.get(session_id=session_id)
        
        return {"cart_id": cart.id}
     # Overriding the destroy method to handle cart item deletion
    def destroy(self, request, *args, **kwargs):
        user = self.request.user
        session_id = self.request.session.session_key or self.request.session.create()

        # Get the cart based on user authentication or session ID
        if user.is_authenticated:
            cart, created = Cart.objects.get_or_create(user=user)
        else:
            cart, created = Cart.objects.get_or_create(session_id=session_id)
        
        # Get the cart item by product_id (provided as pk in the URL)
        product_id = kwargs.get('pk')
        
        product = get_object_or_404(Product, id=product_id)
        
        # Try to find the cart item and delete it
        cart_item = CartItem.objects.filter(cart=cart, product=product).first()

        if cart_item:
            cart_item.delete()  # Delete the cart item
            return Response({"message": "Product removed from cart."}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({"detail": "Product not found in the cart."}, status=status.HTTP_404_NOT_FOUND)

class ProfileViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated , IsBuyer, IsSeller]
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    parser_classes = (MultiPartParser, FormParser)

class RegisterViewSet(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request):
        user_type = request.data.get('user_type')  # 'seller' or 'buyer'
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            # Serialize and sign user data
            user_data = serializer.validated_data
            user_data.pop("confirm_password", None)  # Remove confirm_password
            s = URLSafeTimedSerializer(settings.SECRET_KEY)
            signed_data = s.dumps({"user_data": user_data, "user_type": user_type})
            
            
            # Generate a random 6-digit authentication code
            auth_code = random.randint(100000, 999999)

            # Store auth code in cache (valid for 10 minutes)
            email = user_data["email"]
            cache.set(f"auth_code_{email}", auth_code, timeout=600)
            cache.set(f"user_data_{email}", user_data, timeout=600)
            # Generate email verification link          
            username = user_data["username"]
            current_site = get_current_site(request).domain
            relative_link = reverse('email-verify')
            absurl = f'http://{current_site}{relative_link}?token={signed_data}'
            email_body = (f"Hi {username},\nUse the link below to verify your email:\n{absurl}\n\n"
                        f"Authentication Code: {auth_code}\n"
                       "Enter this code on the registration page to complete your registration."  )

            # Send verification email
            data = {
                "email_body": email_body,
                "to_email": email,
                "email_subject": "Verify your email and authentication code",
            }
            Util.send_email(data)

            return Response(
                {"message": "Verification email sent! Please check your inbox."},
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(APIView):
    
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.GET.get("token")
        if not token:
            return Response({"error": "Token is missing"}, status=status.HTTP_400_BAD_REQUEST)

        s = URLSafeTimedSerializer(settings.SECRET_KEY)

        try:
            # Unsign the token to retrieve user data
            signed_data = s.loads(token, max_age=3600)  # Token valid for 1 hour
            user_data = signed_data["user_data"]
            user_type = signed_data["user_type"]
            if User.objects.filter(email=user_data["email"]).exists():
                return Response(
                    {"message": "User already exists. Email is verified."},
                    status=status.HTTP_200_OK,
                )
            # Create user and assign to group
            user = User.objects.create_user(**user_data)
            user.is_verified = True
            

            if user_type == "seller":
                seller_group = Group.objects.get(name="Seller")
                user.groups.add(seller_group)
            elif user_type == "buyer":
                buyer_group = Group.objects.get(name="Buyer")
                user.groups.add(buyer_group)
            else:
                return Response(
                    {"error": "Invalid user type"}, status=status.HTTP_400_BAD_REQUEST
                )
            user.save()
            return Response({"email": "Successfully activated"}, status=status.HTTP_200_OK)

        except SignatureExpired:
            return Response({"error": "Activation link expired."}, status=status.HTTP_400_BAD_REQUEST)
        except BadSignature:
            return Response({"error": "Invalid activation link."}, status=status.HTTP_400_BAD_REQUEST)
        
class VerifyAuthCodeView(APIView):
    permission_classes = [AllowAny]
    serializer_class = AuthCodeSerializer
    def post(self, request):
        serializer = AuthCodeSerializer(data=request.data)
        if serializer.is_valid():
            email = request.data.get("email")
            auth_code = request.data.get("auth_code")
            
            if not email or not auth_code:
                return Response({"error": "Email and auth code are required."}, status=status.HTTP_400_BAD_REQUEST)
            # Retrieve the stored code from cache
            stored_code = cache.get(f"auth_code_{email}")
            user_data = cache.get(f"user_data_{email}")
            
            if stored_code is None:
                return Response({"error": "Authentication code expired or not found."}, status=status.HTTP_400_BAD_REQUEST)

            if str(stored_code) == str(auth_code):
                if user_data:
                    # You can save the user_data to the database,
                    hashed_password = make_password(user_data['password'])
                    try: 
                        user = User.objects.create(
                            email=user_data['email'],
                            password=hashed_password,
                            username=user_data['username'],
                            user_type=user_data['user_type']
                            # Add any other fields from user_data that you want to store
                        )
                        # Optionally, clear the cache after saving the data
                        cache.delete(f"user_data_{email}")
                        cache.delete(f"auth_code_{email}")
                        return Response({"message": "Authentication code verified!"}, status=status.HTTP_200_OK)
                    except Exception as e:
                        # Catch any errors during user creation
                        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    return Response({"error": "User data not found in cache."}, status=status.HTTP_400_BAD_REQUEST)
                
            else:
                return Response({"error": "Invalid authentication code."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomUserAuthentication:
    def authenticate(self, request):
        user = authenticate(request)
        if user and not user.is_verified:
            raise exceptions.AuthenticationFailed("Email not verified. Please check your inbox.")
        return user

  
class LoginView(APIView):
    
   
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh':str(refresh), 
                'access': str(refresh.access_token),
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        logout(request)
        return Response({"detail": "Successfully logged out"}, status=200)
    

class WishListViewSet(ModelViewSet):
    permission_classes = [AllowAny]
    http_method_names = ["get", "post", "delete"]
    
    def get_queryset(self):
        user = self.request.user
        session_id = self.request.session.session_key 
        if not session_id:
           session_id = self.request.session.create()  # Generate a new session ID if it doesn't exist

        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            # Merge session wishlist into user wishlist
            wishlist, created = Wishlist.objects.get_or_create(user=user)
        else:
            # Return session wishlist for unauthenticated users
            wishlist, created = Wishlist.objects.get_or_create(session_id=session_id)
        return wishlist.products.all()
    def get_serializer_class(self):
        if self.request.method == "POST":
            return WishlistCreateSerializer
        else:
            return WishlistSerializer
        
    def get_serializer_context(self):
        """
        Provide additional context to the serializer.
        """
        user = self.request.user
        session_id = self.request.session.session_key 
        if not session_id:
           session_id = self.request.session.create()  # Generate a new session ID if it doesn't exist

        if user.is_authenticated:
            wishlist, _ = Wishlist.objects.get_or_create(user=user)
        else:
            wishlist, _ = Wishlist.objects.get_or_create(session_id=session_id)
        return {"wishlist_id": wishlist.id}
    def list(self, request, *args, **kwargs):
        """List all products in the wishlist."""
        wishlist = self.get_queryset()  # Fetch products from get_queryset()
        serializer = ProductSerializer(wishlist, many=True)  # Serialize products
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """Add products to the wishlist."""
        user = self.request.user
        session_id = self.request.session.session_key or self.request.session.create()

        # Get wishlist based on user authentication
        if user.is_authenticated:
            wishlist, _ = Wishlist.objects.get_or_create(user=user)
        else:
            wishlist, _ = Wishlist.objects.get_or_create(session_id=session_id)

        serializer = WishlistCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        product_ids = serializer.validated_data["product_id"]
        products = Product.objects.filter(id__in=product_ids)

        wishlist.products.add(*products)
        return Response({"message": "Products added to wishlist successfully."})
        
    def destroy(self, request, *args, **kwargs):
        """Remove a product from the wishlist."""
        user = self.request.user
        session_id = self.request.session.session_key or self.request.session.create()

        # Get wishlist based on user authentication
        if user.is_authenticated:
            wishlist = Wishlist.objects.get(user=user)
        else:
            wishlist = Wishlist.objects.get(session_id=session_id)

        product_id = kwargs.get("pk")
        product = get_object_or_404(Product, id=product_id)

        # Remove product from the wishlist
        wishlist.products.remove(product)
        return Response({"message": "Product removed from wishlist."})
    

class RequestVerificationCodeView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the email already exists in your user model
        if User.objects.filter(email=email).exists():
            return Response({"error": "Email is already registered"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate and save the verification code
        verification, created = EmailVerification.objects.get_or_create(email=email)
        verification.generate_code()
        verification.save()

        # Send the code to the email
        send_verification_email(email, verification.code)
        return Response({"message": "Verification code sent to your email"}, status=status.HTTP_200_OK)

class VerifyCodeAndCreateUserView(APIView):
    
    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')
        username = request.data.get('username')
        password = request.data.get('password')

        if not all([email, code, username, password]):
            return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            verification = EmailVerification.objects.get(email=email, code=code)
        except EmailVerification.DoesNotExist:
            return Response({"error": "Invalid verification code or email"}, status=status.HTTP_400_BAD_REQUEST)

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password)
        verification.delete()  # Clean up after successful verification
        return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)

class RequestPasswordEmail(generics.GenericAPIView): 
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordEmailRequestSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email', '')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            
             # Generate a secure reset code
            reset_code = get_random_string(length=6, allowed_chars='0123456789')
            cache.set(f"password_reset_code_{email}", reset_code, timeout=900)  # Valid for 15 minutes

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = (
                f"Hello, \nUse the link below to reset your password:\n{absurl}?redirect_url={redirect_url}\n\n"
                f"Alternatively, use this code to reset your password: {reset_code}"
            )
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)

class CustomRedirect(HttpResponsePermanentRedirect):
    permission_classes = [AllowAny]
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

class PasswordTokenCheckAPI(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        # Use localhost as the default redirect URL during development
        redirect_url = request.GET.get('redirect_url', 'http://localhost:3000')

        try:
            # Decode the user ID
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            # Validate the token
            if not PasswordResetTokenGenerator().check_token(user, token):
                return CustomRedirect(f"{redirect_url}?token_valid=False&message=Invalid or expired token")

            # If token is valid, redirect with success parameters
            return CustomRedirect(
                f"{redirect_url}?token_valid=True&message=Credentials Valid&uidb64={uidb64}&token={token}"
            )

        except DjangoUnicodeDecodeError:
            # Handle decoding errors gracefully
            return Response({'error': 'Invalid UID encoding'}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            # Handle case where user does not exist
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            # Log unexpected errors for easier debugging in development
            print(f"Unexpected error in PasswordTokenCheckAPI: {str(e)}")
            return Response({'error': 'Unexpected error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SetNewPasswordAPIView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)

class ValidateOTPAndResetPassword(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        email = request.data.get('email', '')
        auth_code = request.data.get('auth_code', '')
        new_password = request.data.get('new_password', '')

        stored_auth_code = cache.get(f"password_reset_code_{email}")

            
        if stored_auth_code is None:
                return Response({"error": "Authentication code expired or not found."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)

            try:
               
                

                # Check if the OTP matches and is valid
                if stored_auth_code == auth_code:
                    # Reset the password
                    user.set_password(new_password)
                    user.save()

                   # Delete the OTP from cache after successful password reset
                    cache.delete(f"password_reset_code_{email}")

                    return Response({'success': 'Password has been reset successfully'}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
            except PasswordResetOTP.DoesNotExist:
                return Response({'error': 'No OTP request found for this user'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
