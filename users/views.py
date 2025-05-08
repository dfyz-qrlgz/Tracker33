from django.shortcuts import render, redirect
from django.http import FileResponse
import os
from django.conf import settings
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from django.contrib.auth import authenticate, login
from .serializers import UserSerializer, UserRegistrationSerializer
from django.contrib.auth import get_user_model
from django.views.generic import UpdateView, CreateView
from django.urls import reverse_lazy
from .forms import CustomUserChangeForm, CustomUserCreationForm
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import CustomUser
from django.contrib import messages

User = get_user_model()

class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = authenticate(username=username, password=password)
        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user': UserSerializer(user).data
            })
        return Response({'error': 'Неверные учетные данные'}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    success_url = reverse_lazy('dashboard')
    template_name = 'users/signup.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        login(self.request, self.object, backend='django.contrib.auth.backends.ModelBackend')
        return response

class ProfileView(LoginRequiredMixin, UpdateView):
    model = CustomUser
    form_class = CustomUserChangeForm
    template_name = 'users/profile.html'
    success_url = reverse_lazy('profile')

    def get_object(self):
        return self.request.user

    def form_valid(self, form):
        messages.success(self.request, 'Профиль успешно обновлен')
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, 'Ошибка при обновлении профиля')
        return super().form_invalid(form)

    def get(self, request, *args, **kwargs):
        if request.headers.get('Accept') == 'application/json':
            serializer = UserSerializer(self.get_object())
            return Response(serializer.data)
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if request.headers.get('Accept') == 'application/json':
            serializer = UserSerializer(self.get_object(), data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Для веб-интерфейса используем стандартную обработку формы
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        return self.form_invalid(form)

def bad_request(request, exception):
    return render(request, 'errors/400.html', status=400)

def permission_denied(request, exception):
    return render(request, 'errors/403.html', status=403)

def page_not_found(request, exception):
    return render(request, 'errors/404.html', status=404)

def server_error(request):
    return render(request, 'errors/500.html', status=500)


def download_tracker(request):
    """
    Представление для скачивания файла трекера
    """
    tracker_path = os.path.join(settings.BASE_DIR, 'dist', 'TimeTracker.exe')
    if not os.path.exists(tracker_path):
        # Если файл не найден в основной директории, попробуем найти его в desktop_app
        tracker_path = os.path.join(settings.BASE_DIR, 'desktop_app', 'dist', 'TimeTracker.exe')
        if not os.path.exists(tracker_path):
            return render(request, 'errors/404.html', status=404)
    
    response = FileResponse(open(tracker_path, 'rb'))
    response['Content-Disposition'] = 'attachment; filename="TimeTracker.exe"'
    return response
