
E-commerce Project API

This project is an e-commerce backend built using Django REST Framework, providing a wide range of functionalities for managing products, orders, users, authentication, and more.

## Features

- **Product Management**: Manage products and product details.
- **Category Management**: Manage product categories.
- **Cart Management**: Create and manage shopping carts and cart items.
- **Order Management**: Place and manage orders, confirm payments, and track order status.
- **Seller Management**: Approve and manage sellers in the admin panel.
- **Authentication and Authorization**: User registration, login, email verification, password reset, and JWT authentication.

## API Endpoints

### Admin Endpoints

- `GET /api/admin/`: List of all admins.
- `GET /api/admin/{id}/`: View details of a specific admin.
- `POST /api/admin/{id}/approve_seller/`: Approve a seller.

### Product Endpoints

- `GET /api/products/`: List all products.
- `GET /api/products/{pk}/`: View product details.

### Category Endpoints

- `GET /api/categories/`: List all categories.
- `GET /api/categories/{pk}/`: View category details.

### Cart Endpoints

- `GET /api/cart/`: List all carts.
- `POST /api/cart/get_or_create_cart/`: Get or create a cart.
- `GET /api/cart/{pk}/`: View cart details.

### CartItem Endpoints

- `GET /api/cartitem/`: List all cart items.
- `GET /api/cartitem/{pk}/`: View cart item details.

### Profile Endpoints

- `GET /api/profile/`: List all profiles.
- `GET /api/profile/{pk}/`: View profile details.

### Wishlist Endpoints

- `GET /api/wishlist/`: List all wishlist items.
- `GET /api/wishlist/{pk}/`: View wishlist item details.

### Order Endpoints

- `GET /api/orders/`: List all orders.
- `POST /api/orders/confirm_payment/`: Confirm payment for an order.
- `GET /api/orders/{pk}/`: View order details.
- `POST /api/orders/{pk}/pay/`: Pay for an order.

### Address Endpoints

- `GET /api/address/`: List all addresses.
- `GET /api/address/{pk}/`: View address details.

### Authentication and Authorization Endpoints

- `POST /api/register/`: Register a new user.
- `POST /api/login/`: Login a user.
- `POST /api/logout/`: Logout a user.
- `POST /api/email-verify/`: Verify email address.
- `POST /api/verify-auth-code/`: Verify authentication code.
- `POST /api/request-reset-email/`: Request password reset email.
- `POST /api/password-reset/{uidb64}/{token}/`: Reset password.
- `POST /api/validate-reset-otp/`: Validate password reset OTP.
- `POST /api/password-reset-complete/`: Complete password reset.

### Country, State, and LGA Endpoints

- `GET /api/countries/`: List all countries.
- `GET /api/states/{country_id}/`: List all states in a specific country.
- `GET /api/lgas/{state_id}/`: List all LGAs (Local Government Areas) in a specific state.

### Shipping Fee Endpoint

- `GET /api/shipping-fee/{lga_id}/`: Get shipping fee for a specific LGA.

### Account Management Endpoints

- `POST /api/delete-account/`: Delete a user account.

### Seller Endpoints

- `GET /seller/sellers/`: List all sellers.
- `GET /seller/sellers/{pk}/`: View seller details.
- `GET /seller/seller-orders/`: List all seller orders.
- `GET /seller/seller-orders/{pk}/`: View seller order details.
- `POST /seller/seller-orders/{pk}/update-status/`: Update order status.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/olaz20/E-commerce-Pro.git
```

2. Navigate to the project directory:

```bash
cd ecommerce
```

3. Create a virtual environment:

```bash
python -m venv venv
```

4. Activate the virtual environment:

   - On Windows:

   ```bash
   .\venv\Scripts\activate
   ```

   - On macOS/Linux:

   ```bash
   source venv/bin/activate
   ```

5. Install dependencies:

```bash
pip install -r requirements.txt
```

6. Apply migrations:

```bash
python manage.py migrate
```

7. Run the development server:

```bash
python manage.py runserver
```
-POSTMAN LINK  https://crimson-robot-501047.postman.co/workspace/New-Team-Workspace~b65e46e7-6d79-49c6-b3f2-d8eced2b90b8/collection/37670289-cf5d09cb-5763-4d84-8445-a6a7884a7139?action=share&creator=37670289&active-environment=37670289-7d4bb8cc-8e47-4ab9-8dff-d1978b3617c5
## Usage

- Once the server is running, you can access the API at `http://127.0.0.1:8000/api/`.

## Contributing

If you'd like to contribute, please fork the repository, create a feature branch, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License.


