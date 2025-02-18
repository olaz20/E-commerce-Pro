import logging
import os
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.cache import cache
from django.http import HttpResponsePermanentRedirect
from django.utils.encoding import DjangoUnicodeDecodeError, smart_str
from django.utils.http import urlsafe_base64_decode
from itsdangerous import BadSignature, Signer
from jwt import ExpiredSignatureError
from rest_framework import generics, status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from services import CustomResponseMixin, EmailService

from .models import Profile
from .serializer import (
    LoginSerializer,
    PasswordResetTokenGenerator,
    ProfileSerializer,
    RegisterSerializer,
    ResetPasswordEmailRequestSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
)

logger = logging.getLogger(__file__)
from django.contrib.auth import get_user_model
User = get_user_model()


class ProfileViewSet(ModelViewSet, CustomResponseMixin):
    permission_classes = [IsAuthenticated]
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    parser_classes = (MultiPartParser, FormParser)

class RegisterViewSet(generics.CreateAPIView, CustomResponseMixin):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return self.custom_response(
                message="Invalid data",
                data=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        user_type_data = serializer.save()  # Get user data without saving it

        # Send the email first
        try:
            email_service = EmailService()
            email_service.send_signup_verification_email(request, user_type_data['user'])

            # Now that the email is sent, save the user
            user = user_type_data['user']
            user.save()

            # Add the user to the correct group based on user_type
            if user_type_data['user_type'] == "seller":
                seller_group, _ = Group.objects.get_or_create(name="Seller")
                user.groups.add(seller_group)
            elif user_type_data['user_type'] == "buyer":
                buyer_group, _ = Group.objects.get_or_create(name="Buyer")
                user.groups.add(buyer_group)

            return self.custom_response(
                status=status.HTTP_201_CREATED,
                message="Registration initiated. Please check your email to verify your account.",
            )
        except Exception as e:
            return self.custom_response(
                message=f"Failed to send email: {str(e)}",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ResendEmailView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        if User.objects.filter(
            email=email
        ).exists():  # Change this construct to get_or_404
            user = User.objects.get(email=email)

            try:
                email_service = EmailService()
                email_service.send_password_reset_email(request, user)
                return self.custom_response(
                    status=status.HTTP_201_CREATED,
                    message="Registration initiated. Please check your email to verify your account.",
                )
            except Exception as e:
                return self.custom_response(
                    message=f"Failed to send email: {str(e)}",
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return self.custom_response(
            status=status.HTTP_404_NOT_FOUND,
            message="No user found with this email address",
        )



class EmailVerifyView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            token = request.query_params.get("token")
            signer = Signer()
            email = signer.unsign(token)

            user = get_user_model().objects.get(email=email)
            user.is_verified = True
            user.save()

        except TypeError as ex:
            logger.error(f"{ex}")
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid request, no token provided",
            )
        except BadSignature as ex:
            logger.error(f"{ex}")
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid or expired token.",
            )

        except User.DoesNotExist as ex:
            logger.error(f"{ex}")
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST, message="User not found."
            )

        return self.custom_response(
            message="Email successfully verified. Your account is now active."
        )


class RequestPasswordEmail(CustomResponseMixin, generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        if User.objects.filter(
            email=email
        ).exists():  # Change this construct to get_or_404
            user = User.objects.get(email=email)

            try:
                email_service = EmailService()
                email_service.send_password_reset_email(request, user)
                return self.custom_response(
                    status=status.HTTP_201_CREATED,
                    message="Registration initiated. Please check your email to verify your account.",
                )
            except Exception as e:
                return self.custom_response(
                    message=f"Failed to send email: {str(e)}",
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return self.custom_response(
            status=status.HTTP_404_NOT_FOUND,
            message="No user found with this email address",
        )


class LoginView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializers = LoginSerializer(data=request.data)

        serializers.is_valid(raise_exception=True)
        user = serializers.validated_data
        refresh = RefreshToken.for_user(user)

        return self.custom_response(
            status=status.HTTP_200_OK,
            message="login successfull",
            data={
                "accessToken": str(refresh.access_token),
                "refreshToken": str(refresh),
            },
        )


class LogoutView(CustomResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return self.custom_response(
                    status=status.HTTP_400_BAD_REQUEST,
                    message="Refresh token is required.",
                )

            token = RefreshToken(refresh_token)
            token.blacklist()
            return self.custom_response(
                status=status.HTTP_200_OK, message="Logout successful."
            )

        except InvalidToken:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid refresh token.",
            )
        except ExpiredSignatureError:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Refresh token has expired.",
            )
        except TokenError:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="An error occurred while processing the refresh token.",
            )
        except Exception as e:
            return self.custom_response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message=f"An unexpected error occurred: {str(e)}",
            )


class CustomRedirect(HttpResponsePermanentRedirect):
    permission_classes = [AllowAny]
    allowed_schemes = [os.environ.get("APP_SCHEME"), "http", "https"]


class PasswordTokenCheckAPI(CustomResponseMixin, generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        # Use localhost as the default redirect URL during development
        redirect_url = request.GET.get("redirect_url", "http://localhost:3000")

        try:
            # Decode the user ID
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            # Validate the token
            if not PasswordResetTokenGenerator().check_token(user, token):
                return CustomRedirect(
                    f"{redirect_url}?token_valid=False&message=Invalid or expired token"
                )

            # If token is valid, redirect with success parameters
            return CustomRedirect(
                f"{redirect_url}?token_valid=True&message=Credentials Valid&uidb64={uidb64}&token={token}"
            )

        except DjangoUnicodeDecodeError:
            # Handle decoding errors gracefully
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid UID encoding",
            )

        except User.DoesNotExist:
            # Handle case where user does not exist
            return self.custom_response(
                status=status.HTTP_404_NOT_FOUND, message="User not found"
            )

        except (
            Exception
        ) as e:  # Don't just catch all exceptions in one, handle each case
            return self.custom_response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Unexpected error occurred",
            )
class VerifyCodeView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        code = request.data.get("code")

        if not email or not code:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Email and code are required.",
            )

        cached_code = cache.get(f"auth_code_{email}")
        if not cached_code:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Verification code expired or not found.",
            )

        if str(cached_code) != str(code):
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid verification code.",
            )

        user_data = cache.get(f"user_data_{email}")

        if not user_data:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="User data is missing or expired.",
            )

        User = get_user_model()
        user = User.objects.filter(email=email).first()

        if not user:
            return self.custom_response(
                status=status.HTTP_404_NOT_FOUND, message="user not found."
            )
        user.is_verified = True
        user.save()
        cache.delete(f"auth_code_{email}")
        cache.delete(f"user_data_{email}")
        return self.custom_response(
            status=status.HTTP_201_CREATED,
            message="Authentication code verified successfully. Your account has been activated.",
        )


class SetNewPasswordAPIView(CustomResponseMixin, generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.custom_response(
            data={"success": True, "message": "Password reset success"},
        )


class ValidateOTPAndResetPassword(CustomResponseMixin, generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        # Extract request data
        email = request.data.get("email", "").strip()
        auth_code = request.data.get("auth_code", "")
        new_password = request.data.get("new_password", "").strip()

        # Validate auth_code format
        try:
            auth_code = int(auth_code)
        except ValueError:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid authentication code format. Must be a numeric value.",
            )

        # Check for required fields
        if not email or not auth_code or not new_password:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="All fields are required.",
            )

        # Retrieve OTP from cache
        stored_auth_code = cache.get(f"password_reset_code_{email}")

        if stored_auth_code is None:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Authentication code expired or not found.",
            )

        # Convert to integer (safe since it was retrieved as a string)
        try:
            stored_auth_code = int(stored_auth_code)
        except ValueError:
            return self.custom_response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Stored authentication code is corrupted.",
            )

        # Verify OTP
        if stored_auth_code != auth_code:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST, message="Invalid OTP."
            )

        # Verify user existence
        if not User.objects.filter(email=email).exists():
            return self.custom_response(
                status=status.HTTP_404_NOT_FOUND,
                message="User with this email does not exist.",
            )

        # Reset user password
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()

        # Clear the OTP from cache
        cache.delete(f"password_reset_code_{email}")

        return self.custom_response(
            message="Password has been reset successfully.",
        )


class VerifiedUserBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            user = User.objects.get(username=username)
            if user.check_password(password) and user.is_verified:
                return user
        except User.DoesNotExist:
            return None
