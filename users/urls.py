from django.urls import path
from .views import (
    UserRegistrationView,
    UserLoginView,
    UserProfileView,
    ProfileView,
    download_tracker
)
from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
    PasswordChangeView,
    PasswordChangeDoneView
)

urlpatterns = [
    # Web interface
    path('profile/', ProfileView.as_view(), name='profile'),
    
    # API endpoints
    path('api/register/', UserRegistrationView.as_view(), name='api-user-register'),
    path('api/login/', UserLoginView.as_view(), name='api-user-login'),
    path('api/profile/', UserProfileView.as_view(), name='api-user-profile'),
    
    # Password reset
    path('password_reset/', PasswordResetView.as_view(
        template_name='account/password_reset.html',
        email_template_name='account/email/password_reset_email.html',
        subject_template_name='account/email/password_reset_subject.txt',
        success_url='/users/password_reset/done/'
    ), name='password_reset'),
    path('password_reset/done/', PasswordResetDoneView.as_view(
        template_name='account/password_reset_done.html'
    ), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(
        template_name='account/password_reset_confirm.html',
        success_url='/users/reset/done/'
    ), name='password_reset_confirm'),
    path('reset/done/', PasswordResetCompleteView.as_view(
        template_name='account/password_reset_complete.html'
    ), name='password_reset_complete'),
    
    # Password change
    path('password_change/', PasswordChangeView.as_view(
        template_name='account/password_change.html',
        success_url='/users/password_change/done/'
    ), name='password_change'),
    path('password_change/done/', PasswordChangeDoneView.as_view(
        template_name='account/password_change_done.html'
    ), name='password_change_done'),
    
    # Скачивание трекера
    path('download-tracker/', download_tracker, name='download_tracker'),
] 