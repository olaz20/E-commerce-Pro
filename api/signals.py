from django.contrib.auth.models import Group, Permission
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from store.models import Cart, Wishlist
from django.contrib.auth.signals import user_logged_in
from store.models import StoreUser
from  django.conf import settings
@receiver(post_migrate)
def create_user_roles(sender, **kwargs):
    admin_group, _ = Group.objects.get_or_create(name='Admin')
    seller_group, _ = Group.objects.get_or_create(name='Seller')
    buyer_group, _ = Group.objects.get_or_create(name='Buyer')
    # Add permissions to groups
    admin_permissions = Permission.objects.all()
    admin_group.permissions.set(admin_permissions)
    # seller permission
    seller_permission = Permission.objects.filter(
        codename__in=['add_product', 'change_product', 'delete_product']
    )
    seller_group.permissions.set(seller_permission)
    # Buyer permissions: can view products and add to cart
    buyer_permissions = Permission.objects.filter(
        codename__in=['view_product', 'add_order']
    )
    buyer_group.permissions.set(buyer_permissions)
    
def assign_user_to_group(user, role):
        group = Group.objects.get(name=role)
        user.groups.add(group)
    
    # Create admin user with environment variables
    #user = StoreUser.objects.create_user(username=settings.ADMIN_USERNAME, password=settings.ADMIN_PASSWORD, user_type="admin",email=settings.ADMIN_EMAIL)
    #assign_user_to_group(user, "Admin")
        
@receiver(user_logged_in)
def merge_carts(sender, request, user, **kwargs):
    # Check for session-based cart
    session_id = request.session.session_key
    session_cart = Cart.objects.filter(session_id=session_id).first()
    user_cart, created = Cart.objects.get_or_create(user=user)

     # Check if the logged-in user is a buyer
    if user.groups.filter(name="Buyer").exists():
        user_cart, created = Cart.objects.get_or_create(user=user)

        if session_cart:
            # Merge session cart into user's cart
            user_cart.merge_with(session_cart)
            # Remove session ID from the cart now that it’s associated with the user
            user_cart.session_id = None
            user_cart.save()
            # Delete the session-based cart
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