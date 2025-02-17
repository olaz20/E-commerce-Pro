from django.shortcuts import  get_object_or_404
from rest_framework.decorators import action
from rest_framework import viewsets, exceptions
from rest_framework.viewsets import ModelViewSet
from rest_framework import status
from store.models import *
from .serializers import *
from django.contrib.auth.models import AnonymousUser
from .filter import *
from rest_framework.generics import ListAPIView
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
import logging
from django.dispatch import receiver
from django.core.mail import send_mail, BadHeaderError
from django.utils.crypto import get_random_string
import requests
from rest_framework.permissions import IsAdminUser
from django.db.models.signals import post_save

# Create your views here.


    

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
def initiate_payment(user,amount, email, order_id):
        # Validate inputs
        
            if not all([user, amount, email, order_id]):
                return Response({"error": "Invalid input parameters"}, status=400)
            
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
                    "consumer_id": user.id,
                },
                "customer": {
                    "email": email,
                    "name": user.username or "Anonymous"
                },
                "customizations": {
                    "title": "Olaz Buy",
                }
            }
            

            try:
                response = requests.post(url, headers=headers, json=data)
                response_data = response.json()
                # Check if Flutterwave returned success
                if response.status_code == 200 and response_data.get("status") == "success":
                    return Response(response_data, status=200)
                else:
                    return Response({"error": response_data.get("message", "Payment initiation failed")}, status=400)
            
            
            except requests.exceptions.RequestException as err:
               return Response({"error": f"Payment initiation error: {str(err)}"}, status=500)
 
class OrderViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, IsBuyer,IsOrderOwner]
    http_method_names = ["get", "patch", "post", "delete", "options", "head"]
    
    
    @action(detail=True, methods=['POST'])
    def pay(self, request, pk):
        order = self.get_object()
        order.PAYMENT_STATUS_CHOICES = Order.PAYMENT_STATUS_PENDING
        order.save()
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

        return initiate_payment(request.user,amount, email, order_id)
        return Response(response, status=200)
    
    @action(detail=False, methods=["POST"])
    def confirm_payment(self, request):
        order_id = request.GET.get("o_id")
        status = request.query_params.get("status")
        tx_ref = request.query_params.get("tx_ref")
        user = request.user
        try:
        # Use only valid fields from the Order model
           order = get_object_or_404(Order, id=order_id, owner=user)
        except Order.DoesNotExist:
           return Response({"error": "Invalid order ID or unauthorized access"}, status=403)
        payment_verification = verify_payment(tx_ref)
        if payment_verification['status'] != 'success':
            order.PAYMENT_STATUS_CHOICES = Order.PAYMENT_STATUS_FAILED
            return Response({
                "msg": "Payment verification failed",
                "data": OrderSerializer(order).data
            })
        order.PAYMENT_STATUS_CHOICES = Order.PAYMENT_STATUS_COMPLETE
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
            try:
                send_plain_text_email(subject, message, [request.user.email])
            except Exception as e:
                # Handle email sending failure
                logging.error(f"Failed to send email: {str(e)}")

        data = {
            "msg": "payment was successful",
            "data": serializer.data
        }
        return Response(data)
    
    
    def get_permissions(self):
        if self.request.method in ["PATCH", "DELETE"]:
            return [IsAdminUser(), IsSeller()]
        return [IsAuthenticated()]
    def create(self, request, *args, **kwargs):
        # Initialize serializer with user ID in the context
        serializer = CreateOrderSerializer(data=request.data, context={"user_id": request.user.id})
        
        # Validate the serializer
        if serializer.is_valid(raise_exception=True):
            # Save the order with the specified payment status
            order = serializer.save(payment_status='P')

            # Fetch item names and calculate total quantity
            item_names = [item.product.name for item in order.order_items.all()]
            total_quantity = sum(item.quantity for item in order.order_items.all())

            # Prepare and send an order confirmation email if the user has an email
            if request.user.email:
                subject = "Order Confirmation"
                message = f"""
                Hi {request.user.username},

                Thank you for your order! Here are the details:
                - Item(s): {', '.join(item_names)}
                - Quantity: {total_quantity}
                - Total Price: ${order.total_price}

                We’ll notify you when your order is shipped.

                Regards,
                Olaz Buy Team
                """
                send_mail(subject, message, 'no-reply@olazbuy.com', [request.user.email])
            # Notify each seller involved in the order
        seller_notifications = {}
        for item in order.order_items.all():
            seller = item.product.seller  # Assuming each product has a 'seller' attribute
            if seller.email:  # Check if the seller has an email
                print(f"Adding order for seller {seller.email}")
                if seller.email not in seller_notifications:
                    seller_notifications[seller.email] = []
                seller_notifications[seller.email].append(item)
        print(seller_notifications)
        for seller_email, items in seller_notifications.items():
            seller_item_names = [item.product.name for item in items]
            seller_total_quantity = sum(item.quantity for item in items)
            seller_subject = "New Order Notification"
            seller_message = f"""
            Hi {seller.email},

            You have received a new order for your product(s). Here are the details:
            - Item(s): {', '.join(seller_item_names)}
            - Quantity: {seller_total_quantity}

            Please prepare the items for shipping.

            Regards,
            Olaz Buy Team
            """
            send_mail(seller_subject, seller_message, 'no-reply@olazbuy.com', [seller_email])

            # Serialize the order data and return it in the response
            response_serializer = OrderSerializer(order)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        
        # If serializer is not valid, return errors (raise_exception=True will raise validation errors automatically)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_serializer_class(self):
        """
        Returns the appropriate serializer class based on the HTTP method.
        """
        if self.request.method == 'POST':
            return CreateOrderSerializer
        elif self.request.method == 'PATCH':
            return UpdateOrderSerializer
        return OrderSerializer

    def get_queryset(self):
        """
        Returns the queryset for authenticated users or an empty queryset for unauthenticated users.
        """
        user = self.request.user
        if not user.is_authenticated:
            return Order.objects.none()
        return Order.objects.filter(owner=user)



                
        
        
        
        
    
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
    @action(detail=False, methods=['get'])
    def get_or_create_cart(self, request):
        user = request.user

        # If the user is authenticated and a Buyer
        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            # Retrieve or create a cart associated with the authenticated user
            cart, created = Cart.objects.get_or_create(user=user)
            if created:
               cart.save()
               print(f"Cart created for user: {user.id}")
            
            else:
                # For unauthenticated users, use the session cart
                session_id = request.session.session_key or request.session.create()
                cart, created = Cart.objects.get_or_create(session_id=session_id)
                if created:
                   cart.save()
             # Merge session cart into user cart if applicable
            if user.is_authenticated:
                session_cart = Cart.objects.filter(session_id=request.session.session_key).first()
                if session_cart and session_cart != cart:
                    for item in session_cart.items.all():
                        if not cart.items.filter(product=item.product).exists():
                            item.cart = cart
                            item.save()
                    session_cart.delete()
            # Return the cart items associated with the current cart
            return Response(CartItemSerializer(cart.items.all(), many=True).data)
   

class CartItemViewSet(ModelViewSet):
    permission_classes = [AllowAny]
    http_method_names = ["get", "post", "patch", "delete"]
    def get_queryset(self):
        user = self.request.user 
        
        # For authenticated users (buyers)
        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            cart, created = Cart.objects.get_or_create(user=user)
            if created:
              cart.save()

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
            cart.save()
        return CartItem.objects.filter(cart=cart)
    
    def get_serializer_class(self):
        if self.request.method == "POST":
            return AddCartItemSerializer
        elif self.request.method == 'PATCH':
            return UpdateCartItemSerializer
        return CartItemSerializer
        
    

    def get_serializer_context(self):
        user = self.request.user

        if user.is_authenticated and user.groups.filter(name="Buyer").exists():
            # Get the user's cart, or handle if not found
            cart = Cart.objects.filter(user=user).first()
            if not cart:
                # Handle the case where no cart is found for the user
                cart = Cart.objects.create(user=user)  # Create a new cart if needed
        else:
            # Use the session-based cart
            session_id = self.request.session.session_key or self.request.session.create()
            cart = Cart.objects.filter(session_id=session_id).first()
            if not cart:
                # Handle the case where no cart is found for the session
                cart = Cart.objects.create(session_id=session_id)  # Create a new cart if needed

        return {"cart_id": cart.id}

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
        # Validate the request data using serializer
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']  # Safely get email after validation

        # Check if a user with this email exists
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            
            # Generate a unique token for the user
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            
            # Generate an OTP and store it in the cache
            reset_code = get_random_string(length=6, allowed_chars='0123456789')
            cache.set(f"password_reset_code_{email}", reset_code, timeout=900)  # Valid for 15 minutes

            # Construct the reset URL
            current_site = get_current_site(request=request).domain
            relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            redirect_url = request.data.get('redirect_url', '')
            absurl = f"http://{current_site}{relative_link}?redirect_url={redirect_url}"

            # Email body with link and code
            email_body = (
                f"Hello,\n\n"
                f"Use the link below to reset your password:\n{absurl}\n\n"
                f"Alternatively, use this code to reset your password: {reset_code}\n\n"
                f"If you didn't request a password reset, please ignore this email."
            )

            # Send the email
            data = {
                'email_body': email_body,
                'to_email': user.email,
                'email_subject': 'Reset Your Password'
            }
            Util.send_email(data)

            # Respond with success
            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)

        # User with provided email does not exist
        return Response({'error': 'No user found with this email address'}, status=status.HTTP_404_NOT_FOUND)

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
        # Extract request data
        email = request.data.get('email', '').strip()
        auth_code = request.data.get('auth_code', '')
        new_password = request.data.get('new_password', '').strip()
        try:
            auth_code = int(auth_code)
        except ValueError:
            return Response({'error': 'Invalid authentication code format. Must be a numeric value.'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        if not email or not auth_code or not new_password:
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)
        stored_auth_code = int(cache.get(f"password_reset_code_{email}"))  
        if stored_auth_code is None:
            return Response({"error": "Authentication code expired or not found."}, status=status.HTTP_400_BAD_REQUEST)


        if not stored_auth_code:
            return Response({"error": "Authentication code expired or not found."}, status=status.HTTP_400_BAD_REQUEST)

        if stored_auth_code != auth_code:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        if not User.objects.filter(email=email).exists():
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()

        # Clear the OTP
        cache.delete(f"password_reset_code_{email}")

        return Response({"success": "Password has been reset successfully."}, status=status.HTTP_200_OK)

class AddressFormView(viewsets.ViewSet):
    """
    A viewset to manage the address for the authenticated user.
    """

    permission_classes = [IsAuthenticated, IsBuyer]

    def get(self, request, *args, **kwargs):
        """
        Fetches all addresses for the authenticated user.
        If no addresses exist, return a message and an empty list.
        """
        # Retrieve all addresses for the authenticated user
        addresses = Address.objects.filter(user=request.user)
        
        if addresses.exists():
            # Serialize the addresses into a list of dictionaries
            address_data = [
                {
                    "id": address.id,
                    "full_name": address.full_name,
                    "phone_number": address.phone_number,
                    "country": address.country.name,
                    "state": address.state.name,
                    "local_government": address.local_government.name,
                    "street_address": address.street_address,
                    "landmark": address.landmark,
                }
                for address in addresses
            ]
            return Response(
                {
                    "message": "Addresses retrieved successfully",
                    "addresses": address_data,
                },
                status=status.HTTP_200_OK,
            )
        else:
            # No addresses found for the user
            return Response(
                {
                    "message": "No addresses found for the user",
                    "addresses": [],
                },
                status=status.HTTP_404_NOT_FOUND,
            )
    def create(self, request, *args, **kwargs):
        """
        Handles creating a new address.
        """
        # Extract data from the request
        address_data = request.data

        # Use a serializer to validate and save the address data
        serializer = AddressSerializer(data=address_data)
        if serializer.is_valid():
            # Save the address to the database
            address = serializer.save(user=self.request.user)
            return Response(
                {
                    "message": "Address created successfully",
                    "address": {
                        "full_name": serializer.data.get("full_name"),
                        "phone_number": serializer.data.get("phone_number"),
                        "country": address.country.name,
                        "state": address.state.name,
                        "local_government": address.local_government.name,
                        "street_address": serializer.data.get("street_address"),
                        "landmark": serializer.data.get("landmark"),
                    },
                },
                status=status.HTTP_201_CREATED,
            )
        else:
            # Return validation errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None, *args, **kwargs):
        """
        Handles partial update (PATCH) of an address.
        """
        try:
            # Retrieve the address object for the authenticated user
            address = Address.objects.get(pk=pk, user=request.user)
        except Address.DoesNotExist:
            return Response(
                {"error": "Address not found or you do not have permission to modify it."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Validate and update the address using the serializer
        serializer = AddressSerializer(address, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "message": "Address updated successfully",
                    "address": {
                        "full_name": serializer.data.get("full_name"),
                        "phone_number": serializer.data.get("phone_number"),
                        "country": address.country.name,
                        "state": address.state.name,
                        "local_government": address.local_government.name,
                        "street_address": serializer.data.get("street_address"),
                        "landmark": serializer.data.get("landmark"),
                    },
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        """
        Handles deleting an address.
        """
        try:
            # Retrieve the address object for the authenticated user
            address = Address.objects.get(pk=pk, user=request.user)
        except Address.DoesNotExist:
            return Response(
                {"error": "Address not found or you do not have permission to delete it."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Delete the address
        address.delete()
        return Response({"message": "Address deleted successfully"}, status=status.HTTP_204_NO_CONTENT)



class CountryListView(ListAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer

class StateListView(ListAPIView):
    def get_queryset(self):
        country_id = self.kwargs['country_id']
        return State.objects.filter(country_id=country_id)
    serializer_class = StateSerializer

class LGAListView(ListAPIView):
    def get_queryset(self):
        state_id = self.kwargs['state_id']
        return LocalGovernment.objects.filter(state_id=state_id)
    serializer_class = LocalGovernmentSerializer

class ShippingFeeView(ListAPIView):
    def get_queryset(self):
        lga_id = self.kwargs['lga_id']
        return ShippingFee.objects.filter(lga_id=lga_id)
    serializer_class = ShippingFeeSerializer
    
class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        # Access the authenticated user
        user = request.user
        # Delete the user
        user.delete()
        return Response({"message": "Your account has been deleted successfully."}, status=status.HTTP_200_OK)