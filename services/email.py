import logging

from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.cache import cache
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import urlsafe_base64_encode

logger = logging.getLogger(__name__)


def send_email_task(subject, recipient_email, template_name, context):
    try:
        html_message = render_to_string(template_name, context)
        email = EmailMessage(
            subject=subject,
            body=html_message,
            to=[recipient_email],
            from_email=context["from_email"],
        )
        email.content_subtype = "html"
        email.send()
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_email}: {str(e)}")
        raise  # Re-raise exception after logging it
class EmailService:
    def __init__(self, default_sender=None):
        self.default_sender = default_sender or settings.DEFAULT_FROM_EMAIL

    def send_email(self, subject, recipient_email, template_name, context):
        context["from_email"] = self.default_sender
        send_email_task(subject, recipient_email, template_name, context)

    def send_signup_verification_email(self, request, user):
        first_name = str(user.first_name).capitalize()
        verification_url = self.create_verification_url(request, user.email)
        auth_code = get_random_string(length=6, allowed_chars="0123456789")
        cache.set(f"auth_code_{user.email}", auth_code, timeout=900)
        user_data = {
            "user": user,
            "first_name": user.first_name,
            "email": user.email,
            "auth_code": auth_code,
        }
        cache.set(f"user_data_{user.email}", user_data, timeout=900)
        context = {
            "user": user,
            "first_name": first_name,
            "verification_url": verification_url,
            "auth_code": auth_code,
        }
        logger.info(f"Sending email to {user.email} with auth code {auth_code}")
        self.send_email(
            subject="Olaz Buy Account Verification",
            recipient_email=user.email,
            template_name="userauth/verification.html",
            context=context,
        )

    def create_verification_url(self, request, email):
        from django.core.signing import Signer

        singer = Signer()
        token = singer.sign(email)
        return f"http://{get_current_site(request).domain}{reverse('email-verify')}?token={token}"

    def send_password_reset_email(self, request, user_obj):
        uidb64 = urlsafe_base64_encode(str(user_obj).encode())
        token = PasswordResetTokenGenerator().make_token(user_obj)
        reset_code = get_random_string(length=6, allowed_chars="0123456789")
        cache.set(f"password_reset_code_{user_obj.email}", reset_code, timeout=900)
        reset_url = f"http://{get_current_site(request).domain}{reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})}"

        context = {"reset_url": reset_url, "reset_code": reset_code}
        self.send_email(
            subject="Reset Your Password",
            recipient_email=user_obj.email,
            template_name="user_auth/password_reset.html",
            context=context,
        )
    def send_order_comfimation_email(self, user, order):
        """Send order confirmation email to user."""
        context = {
            "user": user,
            "order": order,
            "first_name": user.first_name.capitalize(),
            "item_names": [item.product.name for item in order.order_items.all()],
            "total_price": order.total_price
        }
        self.send_email(
            subject="Order Confirmation",
            recipient_email=user.email,
            template_name="shopping/order_confirmation.html",
            context=context,
        )
    def send_payment_email(self, user, order):
        """Send payment initiation email to user."""
        context = {
            "user": user,
            "order": order,
            "first_name": user.first_name.capitalize(),
            "amount": order.total_price,
        }
        self.send_email(
            subject="Payment Initiated",
            recipient_email=user.email,
            template_name="shoping/payment_initiated.html",
            context=context,
        )
    def send_payment_success_email(self, user, order):
            """Send payment success email to user."""
            context = {
                "user": user,
                "order": order,
                "first_name": user.first_name.capitalize(),
                "total_price": order.total_price,
                "item_names": [item.product.name for item in order.order_items.all()],
            }
            self.send_email(
                subject="Payment Successful",
                recipient_email=user.email,
                template_name="shoping/payment_success.html",
                context=context,
            )
    def send_seller_order_notification(self, seller_email, items):
        """Send new order notification to seller."""
        seller_item_names = [item.product.name for item in items]
        seller_total_quantity = sum(item.quantity for item in items)
        
        context = {
            "seller_email": seller_email,
            "item_names": seller_item_names,
            "total_quantity": seller_total_quantity,
        }

        self.send_email(
            subject="New Order Notification",
            recipient_email=seller_email,
            template_name="shoping/seller_order_notification.html",
            context=context,
        )