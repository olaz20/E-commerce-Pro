from django.contrib.auth.models import Group, Permission
from django.contrib.auth.signals import user_logged_in
from django.db.models.signals import post_migrate
from django.dispatch import receiver

from store.models import Cart, Wishlist



@receiver(post_migrate)
def create_user_roles(sender, **kwargs):
    admin_group, _ = Group.objects.get_or_create(name="Admin")
    seller_group, _ = Group.objects.get_or_create(name="Seller")
    buyer_group, _ = Group.objects.get_or_create(name="Buyer")
    # Add permissions to groups
    admin_permissions = Permission.objects.all()
    admin_group.permissions.set(admin_permissions)
    # seller permission
    seller_permission = Permission.objects.filter(
        codename__in=[
            "add_product",
            "change_product",
            "delete_product",
            "change_order",
            "update_order_status",
        ]
    )
    seller_group.permissions.set(seller_permission)
    # Buyer permissions: can view products and add to cart
    buyer_permissions = Permission.objects.filter(
        codename__in=["view_product", "add_order"]
    )
    buyer_group.permissions.set(buyer_permissions)


def assign_user_to_group(user, role):
    group = Group.objects.get(name=role)
    user.groups.add(group)


@receiver(user_logged_in)
def merge_carts(sender, request, user, **kwargs):
    # Get the session ID for the user
    session_id = request.session.session_key or request.session.create()

    # Try to get the session cart (if any)
    session_cart = Cart.objects.filter(session_id=session_id).first()

    # Create or get the user's cart
    user_cart, created = Cart.objects.get_or_create(user=user)

    # If the cart was newly created, ensure the user is linked properly
    if created:
        # This is redundant, since `get_or_create(user=user)` should handle it automatically.
        # user_cart.user = user
        user_cart.save()

    # Check if the user is a buyer and has a session cart
    if user.groups.filter(name="Buyer").exists():
        if session_cart:
            # Merge the session cart into the user's cart
            user_cart.merge_with(session_cart)

            # After merging, ensure the session cart is no longer needed
            user_cart.session_id = None
            user_cart.save()

            # Delete the session cart
            session_cart.delete()


@receiver(user_logged_in)
def merge_wishlists(sender, request, user, **kwargs):
    """
    Merge session-based wishlist into user-based wishlist upon login.
    """
    # Check if the user has a session-based wishlist
    session_id = request.session.session_key
    if not session_id:
        return

    try:
        # Get the session-based wishlist
        session_wishlist = Wishlist.objects.get(session_id=session_id)
    except Wishlist.DoesNotExist:
        return

    # Get or create the user's wishlist
    user_wishlist, created = Wishlist.objects.get_or_create(user=user)

    # Add products from session wishlist to the user wishlist
    for product in session_wishlist.products.all():
        if not user_wishlist.products.filter(id=product.id).exists():
            user_wishlist.products.add(product)

    # Delete the session wishlist after merging
    session_wishlist.delete()
