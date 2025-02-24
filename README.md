
---

# **E-Commerce Backend API**

## 🚀 Overview

This is a **Django REST Framework (DRF)** powered backend for an e-commerce platform. It provides APIs for managing users, products, sellers, orders, authentication, and more.

### 🔗 **Postman Collection**

You can test the API using this **[Postman Collection](https://crimson-robot-501047.postman.co/workspace/New-Team-Workspace~b65e46e7-6d79-49c6-b3f2-d8eced2b90b8/collection/37670289-cf5d09cb-5763-4d84-8445-a6a7884a7139?action=share\&creator=37670289\&active-environment=37670289-7d4bb8cc-8e47-4ab9-8dff-d1978b3617c5)**.

---

## 🛠 Features

- **User Authentication** (Registration, Login, Logout, Email Verification, Password Reset)
- **Product Management** (Categories, Products, Reviews)
- **Seller Management** (⚠️ Admin must verify sellers before they can be active)
- **Order Processing** (Cart, Checkout, Payments)
- **CSV-Based Delivery Import** (Delivery data is migrated using CSV)
- **Rate Limiting** (Implemented to prevent API abuse)
- **RESTful API Design** with Django REST Framework
- **JWT Authentication** for secure access
- **PostgreSQL Database** for data storage
- **Media & Static File Handling**

---

## 🏗️ Installation & Setup

### 1️⃣ Clone the Repository

```sh
$ git clone https://github.com/your-username/ecommerce-backend.git
$ cd ecommerce-backend
```

### 2️⃣ Create & Activate Virtual Environment

```sh
$ python -m venv env
$ source env/bin/activate  # On Windows use `env\Scripts\activate`
```

### 3️⃣ Install Dependencies

```sh
$ pip install -r requirements.txt
```

### 4️⃣ Configure Environment Variables

Create a `.env` file and add the following details:

```
SECRET_KEY=your-secret-key
DEBUG=True
DATABASE_URL=postgres://user:password@localhost:5432/dbname
ALLOWED_HOSTS=*
```

### 5️⃣ Apply Migrations & Create Superuser

```sh
$ python manage.py migrate
$ python manage.py createsuperuser
```

### 6️⃣ Run Development Server

```sh
$ python manage.py runserver
```

---

## 🛒 API Endpoints

### 🔑 Authentication

| Endpoint                        | Method | Description            |
| ------------------------------- | ------ | ---------------------- |
| `/auth/register/`               | POST   | Register new user      |
| `/auth/login/`                  | POST   | Login user             |
| `/auth/logout/`                 | POST   | Logout user            |
| `/auth/email-verify/`           | GET    | Verify email           |
| `/auth/request-password-email/` | POST   | Request password reset |
| `/auth/set-new-password/`       | POST   | Set new password       |

### 📦 Products & Categories

| Endpoint              | Method           | Description                         |
| --------------------- | ---------------- | ----------------------------------- |
| `/api/products/`      | GET, POST        | Get all products / Create a product |
| `/api/products/<id>/` | GET, PUT, DELETE | Get, update, or delete product      |
| `/api/categories/`    | GET              | List all categories                 |

### 🏪 Sellers

| Endpoint                    | Method    | Description                         |
| --------------------------- | --------- | ----------------------------------- |
| `/api/sellers/`             | GET, POST | Get all sellers / Register a seller |
| `/api/seller-orders/`       | GET       | Get seller orders                   |
| `/api/sellers/verify/<id>/` | PUT       | **Admin-only:** Verify a seller     |

⚠️ **Sellers must be verified by the admin before they can sell products.**

### ⭐ Reviews

| Endpoint                               | Method           | Description                     |
| -------------------------------------- | ---------------- | ------------------------------- |
| `/products/<product_id>/reviews/`      | GET, POST        | Get or create product reviews   |
| `/products/<product_id>/reviews/<id>/` | GET, PUT, DELETE | Get, update, or delete a review |

---

## 📂 CSV-Based Delivery Migration

The delivery database is **populated using CSV files**. To import delivery data:

```sh
$ python manage.py import_csv location_data.csv
```

---

## 🔒 Rate Limiting

To **prevent abuse**, **rate limiting** has been implemented for API requests. This restricts the number of requests a user can make within a given time frame.

---

## 🚀 Deployment on Render

1. **Push Code to GitHub**
2. **Create a New Web Service on Render**
3. **Set Up Environment Variables**
4. **Use Gunicorn to Run Django**

```sh
$ pip install gunicorn
$ gunicorn ecommerce.wsgi:application --bind 0.0.0.0:8000
```

5. **Check Logs on Render Dashboard**

---

## 📜 License

This project is open-source and available under the MIT License.

---

