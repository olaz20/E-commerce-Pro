"""
URL configuration for ecommerce project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
    openapi.Info(
        title="NitHub Ecommerce Project API Documentation",
        default_version='v1',
        description="API documentation using Swagger",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="olamoyegunolamidesammy@gmail.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("userauth.urls")) ,
    path("accounts/", include("userauth.urls")),
    path("seller/", include("seller.urls")),
    path("store/", include("store.urls")),
]

if settings.DEBUG:
    # Media Files Handling
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    
    # Static Files Handling
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
