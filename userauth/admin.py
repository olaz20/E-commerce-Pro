from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import Profile, StoreUser


# Customizing the StoreUser admin interface
class StoreUserAdmin(UserAdmin):
    model = StoreUser
    list_display = (
        "username",
        "email",
        "is_verified",
        "is_approved",
        "user_type",
        "role",
    )
    list_filter = ("is_verified", "is_approved", "user_type")
    search_fields = ("username", "email")
    ordering = ("username",)
    fieldsets = UserAdmin.fieldsets + (
        (None, {"fields": ("is_verified", "is_approved", "user_type")}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {"fields": ("is_verified", "is_approved", "user_type")}),
    )


# Customizing the Profile admin interface
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "bio", "picture")
    search_fields = ("name",)


# Registering models with the admin site
admin.site.register(StoreUser, StoreUserAdmin)
admin.site.register(Profile, ProfileAdmin)
