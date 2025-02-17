import logging
import os
from itsdangerous import Signer

from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated, AllowAny,  BasePermission, IsAuthenticatedOrReadOnly
from .serializer  import RegisterSerializer, ProfileSerializer,ResetPasswordEmailRequestSerializer
from django.contrib.auth.models import User
from rest_framework import generics, status
from services import EmailService, CustomResponseMixin
from .models import Profile
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework.parsers import MultiPartParser, FormParser
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from itsdangerous.url_safe import URLSafeTimedSerializer

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

