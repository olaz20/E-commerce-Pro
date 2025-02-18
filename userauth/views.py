import logging
import os
from django.contrib.auth.backends import BaseBackend
from jwt import ExpiredSignatureError

from django.http import HttpResponsePermanentRedirect
from itsdangerous import Signer
from django.core.cache import cache
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.http import urlsafe_base64_decode
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated, AllowAny,  BasePermission, IsAuthenticatedOrReadOnly
from .serializer import (RegisterSerializer, ProfileSerializer,
    ResetPasswordEmailRequestSerializer, PasswordResetTokenGenerator,
    ResetPasswordSerializer, LoginSerializer, SetNewPasswordSerializer)
from django.contrib.auth.models import User
from rest_framework import generics, status
from services import EmailService, CustomResponseMixin
from .models import Profile
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework.parsers import MultiPartParser, FormParser
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from itsdangerous.url_safe import URLSafeTimedSerializer
from django.utils.encoding import DjangoUnicodeDecodeError, smart_str


logger = logging.getLogger(__file__)


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
        user_type = request.data.get('user_type')  # 'seller' or 'buyer'
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(): 
           user_data = serializer.validated_data
        
        try:
            email_service = EmailService()
            email_service.send_signup_verification_email(request, user)

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

    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordEmailRequestSerializer(data=request.data)
        user = serializer.is_valid(raise_exception=True)

        email_service = EmailService()
        email_service.send_signup_verification_email(
            request, user, "email-verify"
        )

        return self.custom_response(
            status=status.HTTP_201_CREATED,
            message="Registration initiated. Please check your email to verify your account.",
        )
class EmailVerifyView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            token = request.query_params.get("token")
            signer = Signer()
            email = signer.unsign(token)

            user = get_user_model().objects.get(email=email)
            user.is_active = True
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

class SetNewPasswordAPIView(CustomResponseMixin, generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.custom_response(
            data={"success": True, "message": "Password reset success"},
        )

class ValidateOTPAndResetPassword(
    CustomResponseMixin, generics.GenericAPIView
):
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