from django.core.mail import send_mail
from django.conf import settings
import threading
from django.core.mail import EmailMessage
def send_verification_email(email, code):
    subject = "Your Verification Code"
    message = f"Your verification code is: {code}"
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)

def send_plain_text_email(subject, message, recipient_list):
    send_mail(
        subject=subject,
        message=message,
        from_email= settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        fail_silently=False,
    )
class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        try:
            self.email.send()
        except Exception as e:
            # Log the exception if there's an error with sending the email
            print(f"Error sending email: {e}")
class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        EmailThread(email).start()