from django.urls import path, include
from rest_framework_nested import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views
from .views import *



router = routers.SimpleRouter()
router.register("products", views.ProductsViewSet, basename="product")
router.register("categories", views.CategoryViewSet, basename="category")
router.register("cart", views.CartViewSet, basename="cart")
router.register("cartitem", views.CartItemViewSet, basename="cartitems")
router.register("profile", views.ProfileViewSet, basename="profile")
router.register("wishlist", views.WishListViewSet, basename="wishlist")
router.register("orders", views.OrderViewSet, basename="orders")
router.register("admin", views.AdminViewSet, basename='admin')
router.register("address", views.AddressFormView, basename='address')



# Explicit routes for APIView-based classes
urlpatterns = [
    path("", include(router.urls)),
    path("request-verification/", views.RequestVerificationCodeView.as_view(), name="request-verification"),
    path("verify-and-signup/", views.VerifyCodeAndCreateUserView.as_view(), name="verify-and-signup"),
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("register/", views.RegisterViewSet.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path('email-verify/', VerifyEmailView.as_view(), name="email-verify"),
    path('verify-auth-code/', VerifyAuthCodeView.as_view(), name='verify-auth-code'),
    path('request-reset-email/', RequestPasswordEmail.as_view(),
         name="request-reset-email"), 
    path('password-reset/<uidb64>/<token>/',
         PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('validate-reset-otp/', ValidateOTPAndResetPassword.as_view(), name='validate-reset-otp'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),
         name='password-reset-complete'),
     path('admin/<id>/approve_seller/', AdminViewSet.as_view({'patch': 'approve_seller'}), name='approve-seller'),
     path('countries/', CountryListView.as_view(), name='country-list'),
    path('states/<int:country_id>/', StateListView.as_view(), name='state-list'),
    path('lgas/<int:state_id>/', LGAListView.as_view(), name='lga-list'),
    path('shipping-fee/<int:lga_id>/', ShippingFeeView.as_view(), name='shipping-fee'),
    path('delete-account/', DeleteAccountView.as_view(), name='delete_account'),
]

