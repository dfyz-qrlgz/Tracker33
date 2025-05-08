"""
URL configuration for Tracker33 project.

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
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from django.views.generic import RedirectView
from django.contrib.auth import views as auth_views
from users import views as user_views
from tracking import urls as tracking_urls
from django.contrib.auth.views import LogoutView
from django.views.generic import TemplateView

class CustomLogoutView(LogoutView):
    http_method_names = ['get', 'post', 'options']
    next_page = '/'
    template_name = 'account/logout.html'

class CustomLoginView(auth_views.LoginView):
    template_name = 'account/login.html'
    redirect_authenticated_user = True
    next_page = 'dashboard'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/', include('tracking.urls')),
    path('', include('tracking.urls')),
    path('register/', user_views.SignUpView.as_view(), name='register'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('accounts/', include([
        path('signup/', user_views.SignUpView.as_view(), name='signup'),
        path('profile/', user_views.ProfileView.as_view(), name='profile'),
        path('download-tracker/', user_views.download_tracker, name='download_tracker'),
        path('password/reset/', auth_views.PasswordResetView.as_view(template_name='users/password_reset.html'), name='password_reset'),
        path('password/reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='users/password_reset_done.html'), name='password_reset_done'),
        path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='users/password_reset_confirm.html'), name='password_reset_confirm'),
        path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'), name='password_reset_complete'),
    ])),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
