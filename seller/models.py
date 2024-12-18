from django.db import models
from django.conf import settings
from store.models import Product
class Seller(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    shop_name = models.CharField(max_length=255)
    # Add any other fields you need

    def __str__(self):
        return self.shop_name
