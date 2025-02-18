from rest_framework import permissions
from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name="Admin").exists()


class IsSeller(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if not request.user.groups.filter(name="Seller").exists():
            return False

        return getattr(request.user, "is_approved", False)


class IsBuyer(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.user.groups.filter(name="Buyer").exists()


class IsOrderOwner(permissions.BasePermission):
    """
    Custom permission to only allow owners of an order to access or modify it.
    """

    def has_object_permission(self, request, view, obj):
        # Check if the user making the request is the owner of the order
        return obj.owner == request.user
