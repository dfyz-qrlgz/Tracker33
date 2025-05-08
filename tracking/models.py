from django.db import models
from users.models import CustomUser
from django.utils import timezone

class Application(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='tracked_apps', null=True, blank=True)
    name = models.CharField(max_length=255, verbose_name='Название приложения')
    process_name = models.CharField(max_length=255, verbose_name='Имя процесса')
    is_active = models.BooleanField(default=True, verbose_name='Активно')
    is_productive = models.BooleanField(default=False, verbose_name='Полезное приложение')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Приложение'
        verbose_name_plural = 'Приложения'
        unique_together = ('user', 'process_name')
        ordering = ['name']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['user', 'is_productive']),
            models.Index(fields=['process_name']),
        ]

    def __str__(self):
        return f"{self.name} ({self.process_name})"

class UserActivity(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, verbose_name='Пользователь')
    application = models.ForeignKey(Application, on_delete=models.CASCADE, verbose_name='Приложение')
    start_time = models.DateTimeField(verbose_name='Время начала')
    end_time = models.DateTimeField(verbose_name='Время окончания')
    duration = models.DurationField(verbose_name='Длительность', null=True, blank=True)
    keyboard_presses = models.IntegerField(default=0, verbose_name='Количество нажатий клавиш')
    
    def save(self, *args, **kwargs):
        # Автоматически вычисляем duration при сохранении
        if self.start_time and self.end_time and (self.duration is None):
            self.duration = self.end_time - self.start_time
        super().save(*args, **kwargs)
        
        # Очищаем кэш после сохранения
        from django.core.cache import cache
        cache.delete(f'user_activity_{self.user.id}')
        cache.delete(f'dashboard_{self.user.id}_{self.start_time.date()}')
        cache.delete(f'statistics_{self.user.id}_None_')
        cache.delete(f'application_list_{self.user.id}')

    class Meta:
        verbose_name = 'Активность пользователя'
        verbose_name_plural = 'Активности пользователей'
        indexes = [
            models.Index(fields=['user', 'start_time']),
            models.Index(fields=['user', 'end_time']),
            models.Index(fields=['application', 'start_time']),
            models.Index(fields=['application', 'end_time']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.application.name}"

class KeyboardActivity(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, verbose_name='Пользователь')
    timestamp = models.DateTimeField(verbose_name='Время')
    key_pressed = models.CharField(max_length=50, verbose_name='Нажатая клавиша')
    application = models.ForeignKey(Application, on_delete=models.CASCADE, verbose_name='Приложение')

    class Meta:
        verbose_name = 'Активность клавиатуры'
        verbose_name_plural = 'Активности клавиатуры'
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['application', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.key_pressed}"

class TimeLog(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='timelogs')
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-start_time']
        indexes = [
            models.Index(fields=['user', 'start_time']),
            models.Index(fields=['user', 'end_time']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.start_time.date()}"

    @property
    def duration(self):
        if self.end_time and self.start_time:
            duration = self.end_time - self.start_time
            hours = duration.total_seconds() / 3600
            return f"{round(hours, 2)} hours"
        return "N/A"
