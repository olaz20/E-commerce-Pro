from django.db import models

from django.contrib.auth.models import User, AbstractUser, Group, Permission
class StoreUser(AbstractUser):
    is_verified = models.BooleanField(default=False)  # New field to check if email is verified
    is_approved =models.BooleanField(default=False)  # to know if the seller have approved by the admin
    USER_TYPE_CHOICES = (
        ('seller', 'Seller'),
        ('buyer', 'Buyer'),
        ('admin', 'Admin'),  # New user type for admins
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='buyer')

    def __str__(self):
        return self.username
    @property
    def role(self):
        # Assumes a user belongs to only one primary group
        group = self.groups.first()
        return group.name if group else "No role assigned"
  
class Profile(models.Model):
    name= models.CharField(max_length=30)
    bio = models.TextField()
    picture = models.ImageField(upload_to= 'img', blank=True, null = True)
    
    def __str__(self):
        return self.name