from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    EmailVerifyView,
    LoginView,
    LogoutView,
    PasswordTokenCheckAPI,
    ProfileViewSet,
    RegisterViewSet,
    RequestPasswordEmail,
    ResendEmailView,
    SetNewPasswordAPIView,
    ValidateOTPAndResetPassword,
    VerifyCodeView,
)

# Create a router for viewsets
router = DefaultRouter()
router.register(r"profiles", ProfileViewSet, basename="profile")

urlpatterns = [
    # Authentication-related routes
    path("auth/register/", RegisterViewSet.as_view(), name="register"),
    path("auth/resend-email/", ResendEmailView.as_view(), name="resend-email"),
    path("auth/email-verify/", EmailVerifyView.as_view(), name="email-verify"),
    path(
        "auth/request-password-email/",
        RequestPasswordEmail.as_view(),
        name="request-password-email",
    ),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    # Password reset-related routes
    path(
        "auth/password-reset/<uidb64>/<token>/",
        PasswordTokenCheckAPI.as_view(),
        name="password-reset",
    ),
    path(
        "auth/set-new-password/",
        SetNewPasswordAPIView.as_view(),
        name="set-new-password",
    ),
    path(
        "auth/validate-otp-and-reset-password/",
        ValidateOTPAndResetPassword.as_view(),
        name="validate-otp-and-reset-password",
    ),
    # Additional authentication-related routes
    path("auth/verify-code/", VerifyCodeView.as_view(), name="verify-code"),
    # Include the viewsets with the router
    path("api/", include(router.urls)),
]
