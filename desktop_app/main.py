import sys
import json
import requests
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                           QPushButton, QLabel, QListWidget, QLineEdit, QCheckBox,
                           QMessageBox, QSystemTrayIcon, QMenu, QAction, QDialog,
                           QFormLayout, QDialogButtonBox, QStatusBar, QProgressBar,
                           QTabWidget, QListWidgetItem, QScrollArea, QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QComboBox)
from PyQt5.QtCore import QTimer, Qt, QUrl, QThread, pyqtSignal, QSettings
from PyQt5.QtGui import QIcon, QDesktopServices
import psutil
from pynput import keyboard, mouse
import pygetwindow as gw
import time
from datetime import datetime, timedelta
import logging
from pathlib import Path
import configparser
import os
import threading
from logging.handlers import RotatingFileHandler
import queue
import sqlite3
from typing import Dict, List, Optional, Any, Tuple
import webbrowser
import re
import warnings
import random
import string
import win32gui
import win32process

def get_base_path():
    """Получение базового пути к ресурсам"""
    try:
        # PyInstaller создает временную папку и хранит путь в _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return Path(base_path)

# Настройка логирования
def setup_logging():
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / 'tracker.log'
    
    # Настройка ротации логов (5 файлов по 1MB каждый)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    
    console_handler = logging.StreamHandler()
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger = logging.getLogger('TimeTracker')
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

class APIClient:
    """Класс для взаимодействия с API сервера"""
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.token = None
        self.app_cache = {}  # Кэш для хранения сопоставления имен приложений и их ID
        # Настройка сессии
        self.session.headers.update({
            'User-Agent': 'TimeTrackerDesktopClient/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
    def login(self, username, password):
        """Авторизация на сервере"""
        try:
            # Выполняем реальный запрос к API для получения токена
            logger.info(f"Попытка авторизации на сервере {self.base_url} с логином {username}")
            
            # Формируем URL для авторизации
            auth_url = f"{self.base_url}/api/token/"
            
            # Отправляем запрос на получение токена
            response = requests.post(
                auth_url,
                json={
                    'username': username,
                    'password': password
                },
                headers={
                    'Content-Type': 'application/json'
                }
            )
            
            # Проверяем ответ
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('access')
                # Устанавливаем токен в заголовки сессии
                self.session.headers.update({
                    'Authorization': f'Bearer {self.token}'
                })
                logger.info("Успешная авторизация на сервере")
                
                # После успешной авторизации получаем список приложений
                self.get_applications()
                
                return True, self.token
            else:
                error_msg = f"Ошибка авторизации: {response.status_code} - {response.text}"
                logger.error(error_msg)
                return False, error_msg
        except Exception as e:
            logger.error(f"Ошибка при авторизации: {e}")
            return False, str(e)
            
    def get_applications(self):
        """Получение списка приложений с сервера"""
        try:
            url = f"{self.base_url}/api/applications/"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                applications = response.json()
                # Сохраняем сопоставление имен приложений и их ID
                for app in applications:
                    app_id = app.get('id')
                    process_name = app.get('process_name', '').lower()
                    name = app.get('name', '').lower()
                    
                    # Сохраняем в кэше по разным ключам
                    if process_name:
                        # Извлекаем только имя файла без пути
                        base_name = os.path.basename(process_name).lower()
                        self.app_cache[base_name] = app_id
                        
                    if name:
                        self.app_cache[name] = app_id
                        
                logger.info(f"Загружено {len(applications)} приложений с сервера")
                return applications
            else:
                logger.error(f"Ошибка при получении приложений: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"Ошибка при получении приложений: {e}")
            return []
            
    def get_application_id(self, app_name):
        """Получение ID приложения по его имени"""
        if not app_name:
            return None
            
        # Приводим к нижнему регистру для сравнения
        app_name_lower = app_name.lower()
        
        # Проверяем точное совпадение
        if app_name_lower in self.app_cache:
            return self.app_cache[app_name_lower]
            
        # Проверяем частичное совпадение
        for cached_name, app_id in self.app_cache.items():
            if app_name_lower in cached_name or cached_name in app_name_lower:
                return app_id
                
        # Если не нашли совпадений, пробуем получить свежий список приложений
        if not self.app_cache:
            self.get_applications()
            # Повторяем поиск после обновления кэша
            return self.get_application_id(app_name)
            
        # Если ничего не нашли, возвращаем первый доступный ID или None
        return next(iter(self.app_cache.values()), None)

    def send_activities(self, activities):
        """Отправка данных о активности на сервер"""
        if not self.token:
            return False, "Нет токена авторизации"
            
        try:
            response = self.session.post(
                f"{self.base_url}/api/activities/",
                json=activities
            )
            
            if response.status_code in [200, 201]:
                return True, response.json()
            else:
                return False, response.text
        except Exception as e:
            logger.error(f"Ошибка при отправке активностей: {e}")
            return False, str(e)


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Авторизация")
        self.api_client = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QFormLayout()
        
        self.server_url = QLineEdit()
        self.server_url.setText("http://127.0.0.1:8000")  # Значение по умолчанию
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        
        layout.addRow("URL сервера:", self.server_url)
        layout.addRow("Имя пользователя:", self.username)
        layout.addRow("Пароль:", self.password)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            Qt.Horizontal, self)
        buttons.accepted.connect(self.authenticate)
        buttons.rejected.connect(self.reject)
        
        layout.addRow(buttons)
        self.setLayout(layout)
        
    def authenticate(self):
        server_url = self.server_url.text()
        username = self.username.text()
        password = self.password.text()
        
        if not all([server_url, username, password]):
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return
            
        self.api_client = APIClient(server_url)
        success, data = self.api_client.login(username, password)
        if success:
            # Сохраняем токен и данные пользователя в конфигурации
            # Получаем доступ к объекту конфигурации через родительское окно
            parent_app = self.parent()
            if parent_app and hasattr(parent_app, 'config'):
                config = parent_app.config
                if not config.has_section('Credentials'):
                    config.add_section('Credentials')
                
                # Сохраняем токен и данные пользователя
                config.set('Credentials', 'api_base_url', server_url.rstrip('/') + '/api/')
                config.set('Credentials', 'auth_token', self.api_client.token)
                config.set('Credentials', 'username', username)
                # Устанавливаем user_id по умолчанию, так как data является токеном, а не словарем
                config.set('Credentials', 'user_id', '1')  # Устанавливаем значение по умолчанию
                
                # Отключаем демо-режим после успешной авторизации
                if not config.has_section('Settings'):
                    config.add_section('Settings')
                config.set('Settings', 'demo_mode', 'False')
                
                # Сохраняем конфигурацию
                parent_app._save_config(config)
                logger.info("Токен авторизации успешно сохранен в конфигурации.")
            
            self.accept()
        else:
            QMessageBox.warning(self, "Ошибка", f"Неверные учетные данные или проблемы с сервером: {data}")

class TimeTrackerApp(QMainWindow):
    # Сигналы для взаимодействия с GUI из других потоков
    activity_processed = pyqtSignal(dict)
    update_status_signal = pyqtSignal(str)
    login_required_signal = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        # Инициализация путей и базовой конфигурации до UI
        self.config_path = Path(get_base_path()) / 'config.ini'
        self.config = self.load_config() 

        # Инициализация session и других атрибутов, зависящих от config
        self.session = requests.Session()
        self.api_base_url = self.config.get('Credentials', 'api_base_url', fallback='http://localhost:8000/api/') 
        self.user_id = self.config.get('Credentials', 'user_id', fallback=None)
        auth_token = self.config.get('Credentials', 'auth_token', fallback=None)
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
        
        # machine_id теперь должен быть корректно загружен или создан в self.load_config()
        # и сохранен в self.config
        self.machine_id = self.config.get('Settings', 'machine_id') 
        if not self.machine_id:
            # Эта ситуация не должна возникать, если load_config и get_machine_id работают правильно,
            # но на всякий случай добавим лог и попытку пересоздать
            logger.error("КРИТИЧЕСКАЯ ОШИБКА: machine_id отсутствует в конфигурации ПОСЛЕ вызова load_config. Попытка исправить.")
            self.machine_id = self.get_machine_id(self.config) 
            if not self.machine_id: 
                logger.critical("Не удалось установить machine_id! Приложение может работать некорректно.")
                # Можно рассмотреть вариант с генерацией временного ID или прерыванием работы
                self.machine_id = "error_machine_id_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))

        # Очередь для активностей
        self.activity_queue = queue.Queue()

        # Атрибуты для отслеживания состояния
        self.current_activity_data = None 
        self.activity_start_time = None 
        self.last_activity_time = time.time() 
        self.idle_threshold_seconds = self.config.getint('Settings', 'idle_threshold_seconds', fallback=300)
        self.is_idle = False 
        self.keyboard_press_count = 0  # Счетчик нажатий клавиш
        # self.active_window_details = {'app_name': '', 'window_title': ''} # Этот атрибут больше не используется
        
        # Кэш для хранения соответствия имен приложений и их ID на сервере
        self.app_cache = {}
        
        # Конфигурация отслеживаемых приложений и игнорируемых процессов
        self.tracked_applications_config = {} 
        self.ignored_processes = ['explorer.exe', 'dllhost.exe', 'ShellExperienceHost.exe', 'SearchUI.exe', 'LockApp.exe', 'System Idle Process']
        self.load_tracked_applications_config() 
        
        # Состояние паузы отслеживания
        self.tracking_paused = False
        self.pause_action = None # Для QAction в меню трея
        
        # Другие таймеры
        self.update_app_list_timer = QTimer(self)
        self.update_app_list_timer.timeout.connect(self.update_app_list)
        self.update_app_list_timer.start(5000)

        self.check_connection_timer = QTimer(self)
        self.check_connection_timer.timeout.connect(self.check_connection)
        self.check_connection_timer.start(30000)

        send_interval_seconds = self.config.getint('Settings', 'send_interval_seconds', fallback=60)
        self.send_data_timer = QTimer(self)
        self.send_data_timer.timeout.connect(self.send_activity_data) 
        self.send_data_timer.start(send_interval_seconds * 1000)

        # UI инициализируется после базовой настройки
        # self.tracker = TimeTracker() 
        self.init_ui() 
        self.init_tray_icon() 
        
        # Настройка слушателей и основного таймера трекинга
        self.setup_activity_listeners_and_tracking_timer() 
        
        # Подключаем сигнал для повторной авторизации
        self.login_required_signal.connect(self.show_login_dialog_if_needed)

        if not auth_token:
             # Используем QTimer.singleShot для вызова диалога логина после инициализации основного окна
             QTimer.singleShot(0, self.show_login_dialog_if_needed)

    def show_login_dialog_if_needed(self):
        # Этот метод будет вызван после того, как главный цикл событий Qt запустится
        # Проверяем еще раз, так как состояние могло измениться
        # Проверяем токен во всех возможных местах
        auth_token = None
        
        # Проверяем токен в секции Credentials
        if self.config.has_section('Credentials') and self.config.has_option('Credentials', 'auth_token'):
            auth_token = self.config.get('Credentials', 'auth_token')
            
        # Если не нашли, проверяем в секции Server
        if not auth_token and self.config.has_section('Server') and self.config.has_option('Server', 'token'):
            auth_token = self.config.get('Server', 'token')
            
        # Если не нашли, проверяем в секции API
        if not auth_token and self.config.has_section('API') and self.config.has_option('API', 'token'):
            auth_token = self.config.get('API', 'token')
            
        # Если не нашли, проверяем в корне файла
        if not auth_token and self.config.has_option('DEFAULT', 'token'):
            auth_token = self.config.get('DEFAULT', 'token')
        if not auth_token:
            logger.info("Токен не найден, вызывается диалог входа.")
            login_dialog = LoginDialog(parent=self) 
            if login_dialog.exec_() == QDialog.Accepted:
                # После успешного логина LoginDialog должен обновить self.config
                # и атрибуты self.api_base_url, self.user_id, self.session.headers
                self.api_base_url = self.config.get('Credentials', 'api_base_url')
                self.user_id = self.config.get('Credentials', 'user_id')
                new_auth_token = self.config.get('Credentials', 'auth_token')
                self.session.headers.update({'Authorization': f'Bearer {new_auth_token}'})
                logger.info("Вход выполнен успешно через диалог.")
                # Перезапускаем таймер отправки данных, если интервал мог измениться
                send_interval_seconds = self.config.getint('Settings', 'send_interval_seconds', fallback=60)
                self.send_data_timer.setInterval(send_interval_seconds * 1000)
                QTimer.singleShot(0, self.send_activity_data)
            else:
                logger.warning("Диалог входа отменен пользователем. Приложение может не функционировать корректно.")
                # Можно закрыть приложение или оставить в ограниченном режиме
                # self.close()
        else:
            logger.info("Пользователь уже аутентифицирован (токен найден).")

    def setup_activity_listeners_and_tracking_timer(self):
        """Настраивает слушателей активности мыши/клавиатуры и таймер трекинга."""
        self.keyboard_listener = None
        self.mouse_listener = None
        try:
            self.keyboard_listener = keyboard.Listener(on_press=self._on_user_activity, on_release=self._on_user_activity)
            self.mouse_listener = mouse.Listener(on_click=self._on_user_activity, on_move=self._on_user_activity, on_scroll=self._on_user_activity)
            self.keyboard_listener.start()
            self.mouse_listener.start()
            logger.info("Слушатели активности мыши и клавиатуры запущены.")
        except Exception as e:
            logger.error(f"Ошибка при запуске слушателей активности: {e}", exc_info=True)
            QMessageBox.warning(self, "Ошибка слушателей", 
                                f"Не удалось запустить слушателей активности мыши/клавиатуры: {e}. "
                                "Отслеживание неактивности может не работать.")

        # Основной таймер для трекинга активного окна и неактивности
        self.tracking_timer = QTimer(self)
        self.tracking_timer.timeout.connect(self.track_active_window_and_idle_state)
        self.tracking_timer.start(1000) 


        
    def _on_user_activity(self, *args):
        """Обработчик событий активности пользователя (мышь, клавиатура)."""
        # Увеличиваем счетчик нажатий клавиш, если это событие клавиатуры
        if len(args) > 0 and isinstance(args[0], keyboard.KeyCode):
            self.keyboard_press_count += 1
            # Добавляем дополнительное логирование для отладки
            logger.info(f"Нажатие клавиши: {args[0]}, текущий счетчик: {self.keyboard_press_count}")
            
            # Если есть текущая активность, добавляем в нее информацию о нажатии клавиш
            if self.current_activity_data:
                self.current_activity_data['keyboard_presses'] = self.keyboard_press_count
                logger.info(f"Добавлено {self.keyboard_press_count} нажатий клавиш в текущую активность")
        
        self.last_activity_time = time.time()
        if self.is_idle:
            logger.info("Пользователь снова активен после периода неактивности.")
            self.is_idle = False
            # Логика возобновления сессии будет в track_active_window_and_idle_state
            # self.handle_idle_state_change(is_now_idle=False) 

    def handle_idle_state_change(self, became_idle=False, became_active=False):
        if became_idle:
            if not self.is_idle: # Убедимся, что состояние действительно меняется
                self.is_idle = True
                logger.info(f"Пользователь стал неактивным (порог: {self.idle_threshold_seconds} сек).") 
                if self.current_activity_data and not self.tracking_paused: # Завершаем сессию только если не на паузе
                    self.end_current_activity_session(event_type="idle_start")
                
                status_message = f"Пользователь неактивен (бездействует > {self.idle_threshold_seconds} сек)."
                if self.tracking_paused:
                    status_message = f"Пользователь неактивен (Отслеживание приостановлено)."
                self.status_bar.showMessage(status_message)
                if self.tray_icon:
                    self.tray_icon.setToolTip(status_message)
        elif became_active:
            if self.is_idle: # Убедимся, что состояние действительно меняется
                self.is_idle = False 
                logger.info("Состояние неактивности завершено. Возобновление отслеживания.")
                status_message = "Пользователь снова активен. Определение окна..."
                if self.tracking_paused:
                    status_message = "Пользователь снова активен (Отслеживание приостановлено)."
                
                self.status_bar.showMessage(status_message)
                if self.tray_icon:
                    self.tray_icon.setToolTip(status_message)
                # track_active_window_and_idle_state подхватит и начнет новую сессию, если нужно (и не на паузе).
                
    def _check_idle_timer(self):
        """Проверяет, не перешел ли пользователь в состояние неактивности."""
        current_time = time.time()
        # Если пользователь активен, но прошло больше idle_threshold_seconds с момента последней активности
        if not self.is_idle and (current_time - self.last_activity_time > self.idle_threshold_seconds):
            logger.info(f"Пользователь неактивен более {self.idle_threshold_seconds} секунд. Переход в состояние неактивности.")
            self.handle_idle_state_change(became_idle=True)

    def load_config(self) -> configparser.ConfigParser:
        """Загружает конфигурацию из файла или создает новую, если файл отсутствует/поврежден."""
        config = configparser.ConfigParser()
        if self.config_path.exists() and self.config_path.is_file():
            try:
                config.read(self.config_path, encoding='utf-8')
                logger.info(f"Конфигурация успешно загружена из {self.config_path}")
                # Проверка на наличие machine_id и его генерация при необходимости
                if not config.has_section('Settings') or \
                   not config.has_option('Settings', 'machine_id') or \
                   not config.get('Settings', 'machine_id'):
                    logger.warning("'machine_id' не найден или пуст в конфигурации. Генерирую новый.")
                    _ = self.get_machine_id(config) # Передаем текущий объект config
                    self._save_config(config) # Сохраняем после обновления machine_id
            except configparser.Error as e:
                logger.error(f"Ошибка чтения конфигурационного файла {self.config_path}: {e}. Создается новый файл.", exc_info=True)
                config = self.create_default_config()
                self.get_machine_id(config)
                self._save_config(config)
            except Exception as e:
                logger.error(f"Непредвиденная ошибка при загрузке конфигурации {self.config_path}: {e}. Создается новый файл.", exc_info=True)
                config = self.create_default_config()
                self.get_machine_id(config)
                self._save_config(config)
        else:
            logger.warning(f"Конфигурационный файл {self.config_path} не найден. Создается новый.")
            config = self.create_default_config()
            self.get_machine_id(config)
            self._save_config(config)

        # Гарантируем наличие основных секций
        default_sections = {
            'Credentials': self.create_default_config().items('Credentials'),
            'Settings': self.create_default_config().items('Settings'),
            'Applications': self.create_default_config().items('Applications')
        }
        
        made_changes_to_config = False
        for section_name, default_items in default_sections.items():
            if not config.has_section(section_name):
                logger.warning(f"Секция [{section_name}] отсутствует в конфигурации. Добавляю стандартную.")
                config.add_section(section_name)
                made_changes_to_config = True
            for key, value in default_items:
                if not config.has_option(section_name, key):
                    logger.warning(f"Опция '{key}' отсутствует в секции [{section_name}]. Добавляю значение по умолчанию.")
                    config.set(section_name, key, value)
                    made_changes_to_config = True
        
        # Повторная проверка machine_id после возможного добавления секции Settings
        if not config.has_option('Settings', 'machine_id') or not config.get('Settings', 'machine_id'):
            logger.warning("machine_id все еще отсутствует после проверки секций. Генерирую.")
            self.get_machine_id(config) # get_machine_id сам вызовет _save_config, если ID генерируется
            made_changes_to_config = True # Отмечаем, что были изменения (хотя save уже был)

        if made_changes_to_config and not (config.has_option('Settings', 'machine_id') and config.get('Settings', 'machine_id')):
             # Если были изменения, кроме генерации machine_id (которая сама сохраняет), то сохраняем
             self._save_config(config)
        elif not self.config_path.exists(): # Если файл изначально не существовал, он был создан и сохранен
            pass # Уже сохранено при создании
        
        return config
        
    def get_machine_id(self, current_config: configparser.ConfigParser) -> str:
        """Получает или генерирует уникальный ID машины."""
        # Эта функция теперь ожидает, что current_config - это уже загруженный объект ConfigParser
        if current_config.has_section('Settings') and \
           current_config.has_option('Settings', 'machine_id') and \
           current_config.get('Settings', 'machine_id'):
            machine_id = current_config.get('Settings', 'machine_id')
            logger.debug(f"Используется существующий machine_id: {machine_id}")
            return machine_id
        else:
            new_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
            logger.info(f"Сгенерирован новый machine_id: {new_id}")
            if not current_config.has_section('Settings'):
                current_config.add_section('Settings')
            current_config.set('Settings', 'machine_id', new_id)
            # Важно: get_machine_id не должен сам сохранять весь конфиг,
            # это должна делать вызывающая функция (load_config или __init__)
            # self._save_config(current_config) # Убрано отсюда, чтобы избежать многократных сохранений
            return new_id

    def create_default_config(self) -> configparser.ConfigParser:
        """Создает объект конфигурации со значениями по умолчанию."""
        config = configparser.ConfigParser()
        logger.debug(f"Создание объекта конфигурации по умолчанию.")

        config['Credentials'] = {
            'api_base_url': 'http://localhost:8000/api/',
            'auth_token': '',
            'user_id': '',
            'username': ''
        }
        config['Settings'] = {
            'machine_id': '', # Будет сгенерирован при первом запуске
            'send_interval_seconds': '60',
            'idle_threshold_seconds': '300',
            'log_level': 'INFO',
            'auto_start_tracking': 'false',
            'minimize_to_tray': 'true',
            'max_send_batch_size': '20',
            'demo_mode': 'False',
            'db_backup_interval_hours': '24'
        }
        config['Applications'] = {
            # 'chrome.exe': 'True',
            # 'code.exe': 'True',
        }
        return config

    def _save_config(self, config_object_to_save: Optional[configparser.ConfigParser] = None):
        """Сохраняет объект конфигурации в файл. Если объект не передан, сохраняет self.config."""
        config_to_save = config_object_to_save if config_object_to_save else self.config
        if not config_to_save:
            logger.error("Попытка сохранить пустой объект конфигурации.")
            return
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as configfile:
                config_to_save.write(configfile)
            logger.info(f"Конфигурация успешно сохранена в {self.config_path}")
        except IOError as e:
            logger.error(f"Ошибка при сохранении конфигурации в файл {self.config_path}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при сохранении конфигурации: {e}", exc_info=True)

    def load_tracked_applications_config(self):
        """Загружает конфигурацию отслеживаемых приложений из self.config."""
        self.tracked_applications_config = {}
        if self.config and self.config.has_section('Applications'):
            for app_name, is_useful_str in self.config.items('Applications'):
                try:
                    # Приводим имя приложения к нижнему регистру для унификации
                    # Значение полезности читаем как boolean
                    self.tracked_applications_config[app_name.lower()] = self.config.getboolean('Applications', app_name)
                except ValueError:
                    logger.warning(f"Некорректное значение для '{app_name}' в секции [Applications]: '{is_useful_str}'. Должно быть True/False. Пропускается.")
            logger.info(f"Загружена конфигурация для {len(self.tracked_applications_config)} приложений из config файла.")
        else:
            logger.info("Секция [Applications] не найдена в конфигурации или self.config не инициализирован. Список отслеживаемых приложений пуст.")

    def track_active_window_and_idle_state(self):
        """Отслеживает активное окно и состояние неактивности пользователя."""
        # 0. Проверяем, не приостановлено ли отслеживание
        if hasattr(self, 'tracking_paused') and self.tracking_paused:
            # Отслеживание приостановлено пользователем
            return
            
        # 1. Проверяем состояние неактивности пользователя
        self._check_idle_timer()
        
        # Если пользователь неактивен (is_idle), то и отслеживать окна не нужно
        if self.is_idle:
            # Пользователь неактивен, не отслеживаем окно
            # logger.debug("Пользователь неактивен, отслеживание окна приостановлено.") 
            return

        # 1. Проверка на переход в состояние неактивности
        if not self.is_idle and (time.time() - self.last_activity_time > self.idle_threshold_seconds):
            logger.debug("Обнаружен переход в состояние неактивности.")
            self.handle_idle_state_change(became_idle=True)

        # Если пользователь неактивен, дальнейшее отслеживание окна не производим
        if self.is_idle:
            # logger.debug("Пользователь неактивен, отслеживание окна приостановлено.") 
            return

        # 2. Пользователь активен, получаем информацию об активном окне
        current_window_info = self.get_active_window_info()

        # 3. Обработка информации об окне
        if current_window_info is None:
            # Нет активного окна или ошибка получения информации
            if self.current_activity_data:
                logger.info("Активное окно не найдено или потеряно. Завершение текущей сессии.")
                self.end_current_activity_session(event_type="no_active_window")
            
            # Обновляем статус-бар и тултип трея
            if not self.is_idle: # Только если не в состоянии idle (там свое сообщение)
                status_message = "Активное окно не определено. Отслеживание приостановлено."
                self.status_bar.showMessage(status_message)
                if hasattr(self, 'tray_icon') and self.tray_icon:
                    self.tray_icon.setToolTip(status_message)
            return

        app_name = current_window_info['app_name']
        window_title = current_window_info['window_title']

        # Проверяем, отслеживается ли это приложение
        app_name_lower = app_name.lower()
        if app_name_lower not in self.tracked_applications_config:
            # Если приложение не отслеживается, завершаем текущую сессию, если она есть
            if self.current_activity_data: 
                logger.debug(f"Переключение на неотслеживаемое приложение '{app_name}'. Завершение сессии.")
                self.end_current_activity_session(event_type="switch_to_untracked_app")
            
            # Обновляем статус-бар и тултип трея
            if not self.is_idle: # Только если не в состоянии idle
                status_message = f"Приложение '{app_name}' не отслеживается."
                self.status_bar.showMessage(status_message)
                if hasattr(self, 'tray_icon') and self.tray_icon:
                    self.tray_icon.setToolTip(status_message)
            return

        # Приложение отслеживаемое. Теперь сравниваем с текущей сессией.
        # Определяем, является ли приложение полезным на основе конфигурации
        # В данном случае предполагаем, что все отслеживаемые приложения полезные
        is_useful = True  # По умолчанию считаем все отслеживаемые приложения полезными
        
        if self.current_activity_data is None:
            # Нет текущей сессии (например, после неактивности или запуска трекера)
            logger.info(f"Начало отслеживания нового окна: App='{app_name}', Title='{window_title[:30]}...' ")
            self.start_new_activity_session(app_name, window_title, is_useful)
        else:
            # Есть текущая сессия, проверяем, не изменилось ли окно/приложение
            if (self.current_activity_data['app_name'] != app_name or 
                self.current_activity_data['window_title'] != window_title):
                logger.info(f"Смена окна/заголовка: "
                            f"Старое: '{self.current_activity_data['app_name']}' - '{self.current_activity_data['window_title'][:30]}...' "
                            f"Новое: '{app_name}' - '{window_title[:30]}...' Завершение старой и начало новой сессии.")
                self.end_current_activity_session(event_type="switch_window_title")
                self.start_new_activity_session(app_name, window_title, is_useful)
            # else: Приложение и заголовок те же, сессия продолжается, ничего не делаем
            # logger.debug(f"Продолжается сессия для {app_name}") 

    def init_ui(self):
        self.setWindowTitle('Time Tracker PRO') 
        self.setGeometry(100, 100, 800, 600)

        # Основной виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Статус подключения
        self.connection_status = QLabel("Статус подключения: Проверка...")
        self.connection_status.setStyleSheet("QLabel { color: gray; }")
        layout.addWidget(self.connection_status)

        # Кнопка открытия веб-интерфейса
        web_button = QPushButton("Открыть веб-интерфейс")
        web_button.clicked.connect(self.open_web_interface)
        layout.addWidget(web_button)

        # Кнопка настроек
        settings_button = QPushButton("Настройки")
        settings_button.clicked.connect(self.show_settings_dialog)
        layout.addWidget(settings_button)

        # Создаем вкладки
        self.tabs = QTabWidget()
        
        # Вкладка "Все приложения"
        all_apps_tab = QWidget()
        all_apps_layout = QVBoxLayout(all_apps_tab)
        self.app_list = QListWidget()
        all_apps_layout.addWidget(self.app_list)
        self.tabs.addTab(all_apps_tab, "Все приложения")
        
        # Вкладка "Полезные приложения"
        productive_tab = QWidget()
        productive_layout = QVBoxLayout(productive_tab)
        self.productive_list = QListWidget()
        productive_layout.addWidget(self.productive_list)
        self.tabs.addTab(productive_tab, "Полезные приложения")
        
        # Вкладка "Неполезные приложения"
        non_productive_tab = QWidget()
        non_productive_layout = QVBoxLayout(non_productive_tab)
        self.non_productive_list = QListWidget()
        non_productive_layout.addWidget(self.non_productive_list)
        self.tabs.addTab(non_productive_tab, "Неполезные приложения")
        
        layout.addWidget(self.tabs)

        # Кнопки управления
        buttons_widget = QWidget()
        buttons_layout = QHBoxLayout(buttons_widget)
        
        self.toggle_button = QPushButton('Включить/Выключить')
        self.toggle_button.clicked.connect(self.toggle_app)
        
        self.toggle_productive_button = QPushButton('Отметить как полезное/неполезное')
        self.toggle_productive_button.clicked.connect(self.toggle_productive)
        
        self.remove_button = QPushButton('Удалить')
        self.remove_button.clicked.connect(self.remove_app)
        
        buttons_layout.addWidget(self.toggle_button)
        buttons_layout.addWidget(self.toggle_productive_button)
        buttons_layout.addWidget(self.remove_button)
        
        layout.addWidget(buttons_widget)

        # Статус отслеживания
        self.status_label = QLabel("Статус: Не отслеживается")
        layout.addWidget(self.status_label)

        # Кнопки управления отслеживанием
        tracking_buttons = QWidget()
        tracking_layout = QHBoxLayout(tracking_buttons)
        
        self.start_button = QPushButton('Начать отслеживание')
        self.stop_button = QPushButton('Остановить отслеживание')
        
        self.start_button.clicked.connect(self.start_tracking)
        self.stop_button.clicked.connect(self.stop_tracking)
        
        tracking_layout.addWidget(self.start_button)
        tracking_layout.addWidget(self.stop_button)
        
        layout.addWidget(tracking_buttons)

        # Добавляем статус бар
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Готов к работе")

    def init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(QIcon(str(get_base_path() / 'icons' / 'icon.png')), self)
        
        tray_menu = QMenu()
        show_action = QAction('Показать', self)
        web_action = QAction('Открыть веб-интерфейс', self)
        quit_action = QAction('Выход', self)
        
        show_action.triggered.connect(self.show)
        web_action.triggered.connect(self.open_web_interface)
        quit_action.triggered.connect(self.safe_exit)
        
        tray_menu.addAction(show_action)
        tray_menu.addAction(web_action)
        tray_menu.addAction(quit_action)

        # Действие для паузы/возобновления
        self.pause_action = QAction("Приостановить отслеживание", self)
        self.pause_action.triggered.connect(self.toggle_tracking_pause)
        tray_menu.addAction(self.pause_action)

        tray_menu.addSeparator()
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

    def update_app_list(self):
        # ... (существующий код update_app_list) ...
        pass 

    def check_connection(self):
        # ... (существующий код check_connection) ...
        pass 

    # def check_dependencies(self): 
    #     pass

    # def check_auth(self): 
    #     pass 

    def safe_exit(self):
        try:
            self.status_bar.showMessage('Завершение работы...')
            if hasattr(self, 'tracker') and self.tracker.is_tracking:
                self.tracker.stop_tracking()
            # Останавливаем все потоки и слушатели
            if hasattr(self, 'keyboard_listener') and self.keyboard_listener:
                self.keyboard_listener.stop()
            if hasattr(self, 'mouse_listener') and self.mouse_listener:
                self.mouse_listener.stop()
            if hasattr(self, 'process_activity_thread') and self.process_activity_thread.is_alive():
                # Даём очереди завершиться
                self.activity_queue.join()
            logger.info('Приложение завершает работу корректно.')
        except Exception as e:
            logger.error(f'Ошибка завершения: {e}')
        finally:
            QApplication.quit()

    def open_web_interface(self):
        """Открытие веб-интерфейса"""
        if hasattr(self, 'api_base_url'):
            webbrowser.open(f"{self.api_base_url}/dashboard/")
        else:
            QMessageBox.warning(self, "Ошибка", "Необходима авторизация")
            self.check_auth()

    def start_tracking(self):
        self.status_label.setText("Статус: Отслеживание активно")
        # self.tracker.start_tracking()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_tracking(self):
        self.status_label.setText("Статус: Отслеживание остановлено")
        # self.tracker.stop_tracking()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def closeEvent(self, event):
        reply = QMessageBox.question(
            self,
            'Выход',
            'Вы действительно хотите выйти из приложения?\nВсе сборы активности будут остановлены.',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.safe_exit()
        else:
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                'Time Tracker',
                'Приложение продолжает работать в фоновом режиме',
                QSystemTrayIcon.Information,
                2000
            )

    def toggle_productive(self):
        """Переключение статуса полезности приложения"""
        current_item = self.app_list.currentItem()
        if not current_item:
            return
            
        app_id = current_item.data(Qt.UserRole)
        try:
            config = self.config
            headers = {'Authorization': f'Token {config.get("API", "token")}'}
            
            response = requests.post(
                f"{config.get('API', 'base_url')}/tracked-apps/{app_id}/toggle_productive/",
                headers=headers
            )
            
            if response.status_code == 200:
                self.update_app_list()
                self.status_bar.showMessage("Статус полезности обновлен")
            else:
                self.status_bar.showMessage("Ошибка при обновлении статуса")
        except Exception as e:
            self.status_bar.showMessage(f"Ошибка: {str(e)}")

    def toggle_app(self):
        """Включение/выключение отслеживания приложения"""
        current_item = self.app_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, 'Ошибка', 'Не выбрано приложение для переключения')
            return
        index = self.app_list.row(current_item)
        app = self.tracked_apps[index]
        if hasattr(self, 'toggle_app_tracking') and callable(self.toggle_app_tracking):
            if self.toggle_app_tracking(app['id']):
                self.update_app_list()
            else:
                QMessageBox.warning(self, 'Ошибка', 'Не удалось изменить статус приложения')
    
    def remove_app(self):
        """Удаляет выбранное приложение из списка отслеживаемых"""
        # Получаем выбранный элемент
        current_item = self.app_list.currentItem()
        if not current_item:
            self.status_bar.showMessage("Не выбрано ни одного приложения")
            return
            
        index = self.app_list.row(current_item)
        app = self.tracked_apps[index]
        app_name = app.get('name', 'Неизвестное приложение')
        
        # Подтверждение удаления
        reply = QMessageBox.question(
            self, 
            'Подтверждение удаления', 
            f'Вы уверены, что хотите удалить приложение "{app_name}" из списка отслеживаемых?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Создаем копию текущего списка отслеживаемых приложений
            new_tracked_config = self.tracked_applications_config.copy()
            
            # Удаляем приложение из списка
            app_key = app_name.lower()
            if app_key in new_tracked_config:
                del new_tracked_config[app_key]
                self.update_tracked_applications_config(new_tracked_config)
                self.status_bar.showMessage(f"Приложение '{app_name}' удалено из списка отслеживаемых")
                
                # Обновляем список приложений в UI
                self.update_app_list()
            else:
                self.status_bar.showMessage(f"Приложение '{app_name}' не найдено в списке отслеживаемых")

    def get_active_window_info(self) -> Optional[Dict[str, str]]:
        """Получает информацию о текущем активном окне (имя процесса и заголовок)."""
        try:
            # Получаем хэндл активного окна
            hwnd = win32gui.GetForegroundWindow()
            if hwnd == 0:
                logger.debug("Активное окно не найдено.")
                return None
                
            # Получаем имя процесса
            _, process_id = win32process.GetWindowThreadProcessId(hwnd)
            process = psutil.Process(process_id)
            app_name = process.name()
            
            # Получаем заголовок окна
            window_title = win32gui.GetWindowText(hwnd)
            
            # Группируем все браузеры в одну категорию
            browser_list = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe', 'brave.exe', 'iexplore.exe', 'safari.exe']
            if any(browser in app_name.lower() for browser in browser_list):
                app_name = 'browser.exe'  # Стандартизируем имя для всех браузеров
                logger.debug(f"Браузер обнаружен, стандартизировано как: {app_name}")
            
            logger.debug(f"Активное окно: PID={process_id}, App='{app_name}', Title='{window_title}'")
            return {
                'app_name': app_name.lower() if app_name else 'unknown', 
                'window_title': window_title if window_title else ''
            }
        except psutil.NoSuchProcess as e:
            logger.warning(f"Процесс не найден: {e}")
            return None
        except psutil.AccessDenied as e:
            logger.warning(f"Доступ запрещен к процессу: {e}")
            return None
        except Exception as e:
            logger.error(f"Неожиданная ошибка в get_active_window_info: {e}", exc_info=True)
            return None

    def is_app_useful(self, app_name: str) -> Optional[bool]:
        """Проверяет, является ли приложение 'полезным' согласно конфигурации.
        
        Args:
            app_name: Имя исполняемого файла приложения (например, 'chrome.exe').
            
        Returns:
            True, если приложение полезное.
            False, если приложение неполезное.
            None, если приложение не найдено в конфигурации (или для него не задан статус).
        """
        app_name_lower = app_name.lower()
        if not self.tracked_applications_config: 
            logger.warning("Конфигурация отслеживаемых приложений пуста или не загружена.")
            # Загружаем ее, если она не была загружена при инициализации (хотя должна была)
            if not hasattr(self, '_tracked_apps_loaded_once'): 
                self.load_tracked_applications_config()
                self._tracked_apps_loaded_once = True

        if app_name_lower in self.tracked_applications_config:
            return self.tracked_applications_config[app_name_lower]
        else:
            # Если приложение не найдено в списке, можно считать его нейтральным или неизвестным
            # Для новой логики, если приложение не в списке, мы его не трекаем или спрашиваем пользователя
            # Пока вернем None, что означает 'не определено / не в списке отслеживаемых'
            logger.debug(f"Приложение '{app_name_lower}' не найдено в конфигурации отслеживаемых.")
            return None

    def start_new_activity_session(self, app_name: str, window_title: str, is_useful: Optional[bool] = None):
        """Начинает отслеживание новой сессии активности для приложения."""
        # Если уже есть активная сессия, завершаем её перед началом новой
        if self.current_activity_data:
            self.end_current_activity_session(event_type="switch")
        
        # Создаем новую запись о текущей активности
        current_time = time.time()
        current_time_utc = datetime.utcnow()
        self.activity_start_time = current_time
        
        self.current_activity_data = {
            'app_name': app_name,
            'window_title': window_title,
            'is_useful': is_useful,
            'start_time': current_time,
            'start_time_iso_utc': current_time_utc.isoformat() + 'Z',
            'machine_id': self.config.get('Settings', 'machine_id', fallback='unknown'),
            'user_id': self.config.get('Credentials', 'user_id', fallback='unknown')
        }
        
        logger.info(
            f"Started new activity session: "
            f"App='{app_name}', "
            f"Title='{window_title[:30]}{'...' if len(window_title) > 30 else ''}, "
            f"Useful='{is_useful}', "
            f"StartUTC='{self.current_activity_data['start_time_iso_utc']}'"
        )
        
        # Обновление статус-бара и тултипа трея
        status_text = f"Отслеживается: {app_name} ({'Полезное' if is_useful else 'Неполезное' if is_useful is not None else 'Статус не определен'}) - {window_title[:30]}..."
        self.status_bar.showMessage(status_text)
        if hasattr(self, 'tray_icon') and self.tray_icon:
            self.tray_icon.setToolTip(status_text)

    def end_current_activity_session(self, event_type: str = "switch") -> Optional[Dict[str, Any]]:
        """Завершает текущую сессию активности, подсчитывает длительность и добавляет в очередь."""
        if not self.current_activity_data or self.activity_start_time is None:
            # Используем self.activity_start_time is None для явной проверки инициализации
            logger.debug("Попытка завершить несуществующую сессию активности.")
            return None
        
        # Вычисляем длительность сессии
        end_time = time.time()
        duration_seconds = round(end_time - self.activity_start_time)
        
        if duration_seconds < 1:
            logger.debug(f"Сессия для {self.current_activity_data['app_name']} слишком короткая ({duration_seconds} сек), игнорируется.")
            self.current_activity_data = None
            self.activity_start_time = None
            return None
        
        # Формируем запись для очереди
        activity_entry = self.current_activity_data.copy()
        
        # Добавляем данные о клавиатурной активности
        if 'keyboard_presses' not in activity_entry and self.keyboard_press_count > 0:
            activity_entry['keyboard_presses'] = self.keyboard_press_count
            logger.info(f"Добавлено {self.keyboard_press_count} нажатий клавиш в активность")
            # Сбрасываем счетчик после добавления в активность
            self.keyboard_press_count = 0
        
        activity_entry.update({
            'end_time': end_time,
            'end_time_iso_utc': datetime.utcnow().isoformat() + 'Z',
            'duration_seconds': duration_seconds,
            'event_type': event_type
        })
        
        # Добавляем в очередь для отправки
        self.activity_queue.put(activity_entry)
        
        logger.info(
            f"Завершена сессия активности: "
            f"App='{activity_entry['app_name']}', "
            f"Title='{activity_entry['window_title'][:30]}{'...' if len(activity_entry['window_title']) > 30 else ''}, "
            f"Duration={duration_seconds}s. В очереди: {self.activity_queue.qsize()}"
        )
        
        # Обновление статус-бара и тултипа трея
        status_message = f"Сессия для '{activity_entry['app_name']}' завершена. В очереди: {self.activity_queue.qsize()}"
        self.status_bar.showMessage(status_message)
        if hasattr(self, 'tray_icon') and self.tray_icon:
            # Для тултипа можно показать более общее сообщение после завершения сессии
            tooltip_message = f"Готов к отслеживанию. В очереди: {self.activity_queue.qsize()}"
            if self.is_idle: # Если перешли в idle, то сообщение будет другим из handle_idle_state_change
                 tooltip_message = f"Пользователь неактивен. В очереди: {self.activity_queue.qsize()}"
            self.tray_icon.setToolTip(tooltip_message)
            
        # Очистка данных текущей сессии
        self.current_activity_data = None
        self.activity_start_time = None
        return activity_entry
        
    def get_discovered_applications(self) -> List[str]:
        """Возвращает список уникальных имен запущенных приложений."""
        discovered_apps = set()
        try:
            for proc in psutil.process_iter(['name']):
                try:
                    app_name = proc.info['name']
                    if app_name and app_name.strip(): # Проверяем, что имя не пустое
                        # Приводим к нижнему регистру для унификации
                        discovered_apps.add(app_name.lower())
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Эти исключения ожидаемы для некоторых процессов
                    continue 
                except Exception as e:
                    logger.debug(f"Ошибка при получении имени процесса {proc.pid if hasattr(proc, 'pid') else 'N/A'}: {e}")
        except Exception as e:
            logger.error(f"Ошибка при итерации по процессам: {e}", exc_info=True)
        
        # Можно добавить фильтрацию по self.ignored_processes, если это нужно глобально,
        # или оставить это на усмотрение SettingsDialog
        # filtered_apps = {app for app in discovered_apps if app not in self.ignored_processes}
        
        logger.debug(f"Обнаруженные приложения: {sorted(list(discovered_apps))}")
        return sorted(list(discovered_apps))

    def update_tracked_applications_config(self, new_tracked_config: Dict[str, bool]):
        """Обновляет конфигурацию отслеживаемых приложений и сохраняет ее."""
        logger.info("Обновление конфигурации отслеживаемых приложений.")
        self.tracked_applications_config = new_tracked_config
        
        if not self.config.has_section('Applications'):
            self.config.add_section('Applications')
        else:
            # Очищаем старые записи в секции [Applications]
            for key in self.config.options('Applications'):
                self.config.remove_option('Applications', key)
        
        # Добавляем новые записи
        for app_name, is_useful in new_tracked_config.items():
            self.config.set('Applications', app_name.lower(), str(is_useful))
            
        self._save_config() # Сохраняем весь config.ini
        logger.info("Конфигурация отслеживаемых приложений успешно обновлена и сохранена.")
        # После обновления может потребоваться перерисовать UI или перезагрузить какие-то данные
        # Например, если SettingsDialog открыт, его можно уведомить, или он сам закроется.

    def show_settings_dialog(self):
        dialog = SettingsDialog(self) # Передаем ссылку на главное окно
        dialog.exec_()

    def toggle_tracking_pause(self):
        self.tracking_paused = not self.tracking_paused
        if self.tracking_paused:
            logger.info("Отслеживание приостановлено пользователем.")
            if self.current_activity_data:
                # Завершаем текущую сессию, если она была
                self.end_current_activity_session(event_type="tracking_paused")
            
            msg = "Отслеживание приостановлено."
            self.status_bar.showMessage(msg)
            if self.tray_icon:
                self.tray_icon.setToolTip(msg)
            if self.pause_action: 
                self.pause_action.setText("Возобновить отслеживание")
        else:
            logger.info("Отслеживание возобновлено пользователем.")
            # При возобновлении, track_active_window_and_idle_state само определит активность
            # и начнет новую сессию, если это необходимо.
            # Состояние is_idle также будет актуальным благодаря _check_idle_timer.
            msg = "Отслеживание возобновлено. Определение активности..."
            if self.is_idle:
                 msg = "Отслеживание возобновлено (Пользователь неактивен)."

            self.status_bar.showMessage(msg)
            if self.tray_icon:
                self.tray_icon.setToolTip(msg)
            if self.pause_action: 
                self.pause_action.setText("Приостановить отслеживание")

    def send_activity_data(self):
        """Отправляет накопленные данные активности на сервер."""
        if self.activity_queue.empty():
            logger.debug("Очередь активностей пуста, нечего отправлять.")
            return
            
        # Проверяем, включен ли демо-режим
        demo_mode = self.config.getboolean('Settings', 'demo_mode', fallback=False)
        
        if demo_mode:
            # В демо-режиме просто очищаем очередь и логируем данные
            max_batch_size = self.config.getint('Settings', 'max_send_batch_size', fallback=20)
            activities_to_send = []
            
            # Собираем до max_batch_size активностей из очереди
            for _ in range(min(max_batch_size, self.activity_queue.qsize())):
                if not self.activity_queue.empty():
                    activity = self.activity_queue.get()
                    activities_to_send.append(activity)
            
            logger.info(f"Демо-режим: Обработано {len(activities_to_send)} записей активности. Данные не отправляются на сервер.")
            return
        
        # Получаем API URL из конфигурации
        # Проверяем разные возможные места хранения токена
        auth_token = None
        
        # Проверяем токен в секции Credentials
        if self.config.has_section('Credentials') and self.config.has_option('Credentials', 'auth_token'):
            auth_token = self.config.get('Credentials', 'auth_token')
            
        # Если не нашли, проверяем в секции Server
        if not auth_token and self.config.has_section('Server') and self.config.has_option('Server', 'token'):
            auth_token = self.config.get('Server', 'token')
            
        # Если не нашли, проверяем в секции API
        if not auth_token and self.config.has_section('API') and self.config.has_option('API', 'token'):
            auth_token = self.config.get('API', 'token')
            
        # Если не нашли, проверяем в корне файла
        if not auth_token and self.config.has_option('DEFAULT', 'token'):
            auth_token = self.config.get('DEFAULT', 'token')
            
        # Получаем URL API
        api_url = None
        if self.config.has_section('Credentials') and self.config.has_option('Credentials', 'api_base_url'):
            api_url = self.config.get('Credentials', 'api_base_url')
        elif self.config.has_section('Server') and self.config.has_option('Server', 'base_url'):
            api_url = self.config.get('Server', 'base_url')
        elif self.config.has_section('API') and self.config.has_option('API', 'base_url'):
            api_url = self.config.get('API', 'base_url')
        elif self.config.has_option('DEFAULT', 'base_url'):
            api_url = self.config.get('DEFAULT', 'base_url')
        else:
            api_url = 'http://localhost:8000'
            
        # Добавляем /api/ если необходимо
        if not api_url.endswith('/api/'):
            api_url = api_url.rstrip('/') + '/api/'
            
        api_url += 'activities/'
        
        if not auth_token:
            logger.warning("Отсутствует токен авторизации. Переключение в демо-режим.")
            # Включаем демо-режим
            if not self.config.has_section('Settings'):
                self.config.add_section('Settings')
            self.config.set('Settings', 'demo_mode', 'True')
            self._save_config(self.config)
            return
            
        # Заголовки для запроса
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {auth_token}'
        }
        
        # Обновляем заголовки сессии
        self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
        
        # Собираем пакет данных для отправки
        max_batch_size = self.config.getint('Settings', 'max_send_batch_size', fallback=20)
        activities_to_send = []
        activities_to_send_payload = []
        
        try:
            # Собираем до max_batch_size активностей из очереди
            for _ in range(min(max_batch_size, self.activity_queue.qsize())):
                if self.activity_queue.empty():
                    break
                activity_dict = self.activity_queue.get_nowait()
                activities_to_send.append(activity_dict)
                
                # Формируем данные для API
                # Убедимся, что все обязательные поля заполнены
                start_time = activity_dict.get('start_time_iso_utc', '')
                end_time = activity_dict.get('end_time_iso_utc', '')
                
                # Если поля не заполнены, сгенерируем текущие значения
                if not start_time:
                    start_time = datetime.utcnow().isoformat() + 'Z'
                if not end_time:
                    end_time = datetime.utcnow().isoformat() + 'Z'
                
                # Сервер ожидает определенный формат данных
                # Добавляем все обязательные поля
                duration_seconds = activity_dict.get('duration_seconds', 0)
                if duration_seconds is None or duration_seconds == 0:
                    duration_seconds = 1  # Минимальная длительность
                
                # Вычисляем длительность на основе start_time и end_time
                try:
                    start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                    end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                    # Вычисляем разницу во времени
                    time_diff = end_dt - start_dt
                    calculated_seconds = time_diff.total_seconds()
                    
                    if calculated_seconds <= 0:
                        calculated_seconds = duration_seconds if duration_seconds > 0 else 1
                        # Создаем объект timedelta для поля duration
                        duration_obj = timedelta(seconds=calculated_seconds)
                    else:
                        # Используем реальную разницу во времени
                        duration_obj = time_diff
                except Exception as e:
                    logger.error(f"Ошибка при вычислении длительности: {e}")
                    calculated_seconds = duration_seconds if duration_seconds > 0 else 1
                    duration_obj = timedelta(seconds=calculated_seconds)
                    
                # Изменяем формат запроса, чтобы соответствовать ожиданиям сервера
                # Хотя в сериализаторе поле duration помечено как read_only_fields,
                # сервер всё равно ожидает это поле при вставке в базу данных
                # Попробуем модифицировать серверную часть
                
                # Добавляем отладочную информацию
                logger.info(f"Вычисленная длительность: {calculated_seconds} секунд")
                
                # Определяем ID приложения на основе имени процесса
                app_name = activity_dict.get('app_name', '')
                
                # Создаем новое приложение на сервере, если оно еще не существует
                app_id = None
                
                # Проверяем, есть ли уже такое приложение в кэше
                if app_name.lower() in self.app_cache:
                    app_id = self.app_cache[app_name.lower()]
                    logger.debug(f"Найден ID в кэше для {app_name}: {app_id}")
                else:
                    # Если нет в кэше, создаем новое приложение на сервере
                    try:
                        # Создаем новое приложение
                        app_data = {
                            'name': app_name,
                            'process_name': app_name,
                            'is_productive': False  # По умолчанию не продуктивное
                        }
                        
                        # Отправляем запрос на создание приложения
                        app_url = f"{self.api_base_url}applications/"
                        logger.info(f"Отправляем запрос на создание приложения: {app_url}")
                        app_response = self.session.post(app_url, json=app_data)
                        
                        if app_response.status_code == 201:  # Создано успешно
                            app_data = app_response.json()
                            app_id = app_data.get('id')
                            # Сохраняем в кэш
                            self.app_cache[app_name.lower()] = app_id
                            logger.info(f"Создано новое приложение: {app_name} с ID={app_id}")
                        else:
                            # Если не удалось создать, используем ID=1 по умолчанию
                            app_id = 1
                            logger.warning(f"Не удалось создать приложение {app_name}, используем ID по умолчанию")
                    except Exception as e:
                        # В случае ошибки используем ID=1
                        app_id = 1
                        logger.error(f"Ошибка при создании приложения {app_name}: {e}")
                
                # Если все равно не получили ID, используем значение по умолчанию
                if app_id is None:
                    app_id = 1
                    
                # Для отладки выводим информацию о выбранном ID
                logger.info(f"Для приложения {app_name} выбран ID={app_id}")
                
                # Добавляем количество нажатий клавиш в пайлоад
                keyboard_presses = activity_dict.get('keyboard_presses', 0)
                if keyboard_presses == 0 and self.keyboard_press_count > 0:
                    keyboard_presses = self.keyboard_press_count
                    # Сбрасываем счетчик после отправки
                    logger.info(f"Отправляем клавиатурную активность: {self.keyboard_press_count} нажатий")
                    self.keyboard_press_count = 0
                    
                api_payload = {
                    'application': app_id,  # Используем правильный ID приложения
                    'title': activity_dict.get('window_title', ''),
                    'start_time': start_time,
                    'end_time': end_time,
                    # Не отправляем duration, так как сервер вычислит его автоматически
                    'is_productive': activity_dict.get('is_useful', False),
                    'app_name': app_name,
                    'keyboard_presses': keyboard_presses  # Добавляем количество нажатий клавиш
                }
                
                # Добавляем отладочную информацию
                logger.info(f"Отправка активности: start_time={start_time}, end_time={end_time}, длительность={calculated_seconds} секунд")
                activities_to_send_payload.append(api_payload)
            
            if not activities_to_send_payload:
                logger.debug("Нет данных для отправки после фильтрации.")
                return
                
            # Отправляем данные на сервер
            logger.info(f"Отправка {len(activities_to_send_payload)} записей активности на сервер.")
            logger.info(f"API URL: {api_url}, Токен: {auth_token[:10]}...")
            
            # Сервер ожидает отдельные записи, а не массив
            # Отправляем каждую запись по отдельности
            success_count = 0
            for payload in activities_to_send_payload:
                try:
                    # Добавляем отладочную информацию о пайлоаде
                    logger.info(f"Отправляем пайлоад: {payload}")
                    response = self.session.post(api_url, json=payload, headers=headers, timeout=30)
                    if response.status_code in [200, 201]:
                        success_count += 1
                        logger.info(f"Успешно отправлено: {response.status_code} - {response.text}")
                    elif response.status_code == 401:
                        # Ошибка авторизации - токен недействителен
                        logger.error(f"Ошибка авторизации: {response.status_code} - {response.text}")
                        
                        # Удаляем недействительный токен из конфигурации
                        if self.config.has_section('Credentials') and self.config.has_option('Credentials', 'auth_token'):
                            self.config.set('Credentials', 'auth_token', '')
                        if self.config.has_section('Server') and self.config.has_option('Server', 'token'):
                            self.config.set('Server', 'token', '')
                        if self.config.has_section('API') and self.config.has_option('API', 'token'):
                            self.config.set('API', 'token', '')
                        if self.config.has_option('DEFAULT', 'token'):
                            self.config.set('DEFAULT', 'token', '')
                            
                        # Сохраняем обновленную конфигурацию
                        self._save_config(self.config)
                        
                        # Запрашиваем повторную авторизацию
                        logger.info("Требуется повторная авторизация. Запрашиваем новый токен...")
                        
                        # Сигнал для показа диалога авторизации
                        self.login_required_signal.emit()
                        
                        # Возвращаем все активности обратно в очередь для повторной отправки
                        for activity in activities_to_send:
                            self.activity_queue.put(activity)
                        
                        # Прерываем отправку
                        return
                    else:
                        logger.error(f"Ошибка при отправке записи: {response.status_code} - {response.text}")
                        # Возвращаем активность обратно в очередь
                        for i, activity in enumerate(activities_to_send):
                            if activity.get('app_name') == payload.get('app_name') and activity.get('start_time_iso_utc') == payload.get('start_time'):
                                self.activity_queue.put(activity)
                                break
                except Exception as e:
                    logger.error(f"Ошибка при отправке записи: {e}")
            
            # Создаем фиктивный ответ для обработки в основном коде
            class DummyResponse:
                def __init__(self, status_code):
                    self.status_code = status_code
                    self.text = f"Успешно отправлено {success_count} из {len(activities_to_send_payload)} записей"
            
            response = DummyResponse(200 if success_count > 0 else 400)
            
            if response.status_code == 200 or response.status_code == 201:
                logger.info(f"Успешно отправлено {len(activities_to_send_payload)} записей активности.")
                self.status_bar.showMessage(f"Отправлено {len(activities_to_send_payload)} записей активности.")
            elif response.status_code == 401:
                logger.warning("Токен недействителен, требуется повторная авторизация.")
                # Удаляем устаревший токен из секций Credentials, Server, API и DEFAULT
                if self.config.has_section('Credentials') and self.config.has_option('Credentials', 'auth_token'):
                    self.config.remove_option('Credentials', 'auth_token')
                if self.config.has_section('Server') and self.config.has_option('Server', 'token'):
                    self.config.remove_option('Server', 'token')
                if self.config.has_section('API') and self.config.has_option('API', 'token'):
                    self.config.remove_option('API', 'token')
                if self.config.has_option(self.config.default_section, 'token'):
                    self.config.remove_option(self.config.default_section, 'token')
                # Включаем демо-режим до повторной авторизации
                if not self.config.has_section('Settings'):
                    self.config.add_section('Settings')
                self.config.set('Settings', 'demo_mode', 'True')
                # Сохраняем конфигурацию и очищаем заголовок авторизации
                self._save_config(self.config)
                self.session.headers.pop('Authorization', None)
                # Запрашиваем повторную авторизацию
                QTimer.singleShot(0, self.show_login_dialog_if_needed)
                # Возвращаем активности обратно в очередь
                for activity in activities_to_send:
                    self.activity_queue.put(activity)
                return
            else:
                logger.error(f"Ошибка при отправке данных: {response.status_code} - {response.text}")
                self.status_bar.showMessage(f"Ошибка отправки данных: {response.status_code}")
                # Возвращаем активности обратно в очередь
                for activity in activities_to_send:
                    self.activity_queue.put(activity)
        except requests.RequestException as e:
            logger.error(f"Ошибка сети при отправке данных: {e}", exc_info=True)
            self.status_bar.showMessage(f"Ошибка сети: {str(e)[:50]}...")
            # Возвращаем активности обратно в очередь
            for activity in activities_to_send:
                self.activity_queue.put(activity)
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при отправке данных: {e}", exc_info=True)
            self.status_bar.showMessage(f"Ошибка: {str(e)[:50]}...")
            # Возвращаем активности обратно в очередь
            for activity in activities_to_send:
                self.activity_queue.put(activity)

    def show_settings_dialog(self):
        dialog = SettingsDialog(self) # Передаем ссылку на главное окно
        dialog.exec_()


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent # Сохраняем ссылку на главное окно для доступа к его данным/методам
        self.setWindowTitle("Настройки отслеживания")
        self.setGeometry(200, 200, 700, 500) # Немного увеличим размер
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        self.app_list_widget = QTableWidget()
        self.app_list_widget.setColumnCount(3)
        self.app_list_widget.setHorizontalHeaderLabels(["Приложение (имя процесса)", "Отслеживать", "Статус полезности"])
        self.app_list_widget.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.app_list_widget.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.app_list_widget.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.app_list_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.app_list_widget.setEditTriggers(QAbstractItemView.NoEditTriggers) # Запрет редактирования текста ячеек напрямую
        
        layout.addWidget(self.app_list_widget)

        # Кнопки Сохранить и Отмена
        self.button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept) # accept - стандартный слот QDialog
        self.button_box.rejected.connect(self.reject) # reject - стандартный слот QDialog
        layout.addWidget(self.button_box)

        self.setLayout(layout)
        self.load_settings()

    def load_settings(self):
        logger.debug("Загрузка настроек в SettingsDialog...")
        current_tracked_config = self.main_window.tracked_applications_config
        discovered_apps_list = self.main_window.get_discovered_applications()

        # Объединяем известные отслеживаемые приложения и обнаруженные
        all_apps_to_display = set(discovered_apps_list) # Начинаем с обнаруженных
        all_apps_to_display.update(current_tracked_config.keys()) # Добавляем те, что уже в конфиге
        
        sorted_app_list = sorted(list(all_apps_to_display))

        self.app_list_widget.setRowCount(len(sorted_app_list))

        for row, app_name in enumerate(sorted_app_list):
            app_name_item = QTableWidgetItem(app_name)
            # app_name_item.setFlags(app_name_item.flags() & ~Qt.ItemIsEditable) # Делаем имя нередактируемым

            # Чекбокс "Отслеживать"
            checkbox_widget = QCheckBox()
            checkbox_widget.setStyleSheet("margin-left:10px; margin-right:10px;") # Для центрирования
            is_tracked = app_name in current_tracked_config
            checkbox_widget.setChecked(is_tracked)
            
            # Комбо-бокс "Статус"
            status_combo = QComboBox()
            status_combo.addItems(["Полезное", "Неполезное"])
            if is_tracked:
                is_useful = current_tracked_config.get(app_name, True) # По умолчанию True, если вдруг нет ключа
                status_combo.setCurrentIndex(0 if is_useful else 1)
            else:
                status_combo.setCurrentIndex(0) # По умолчанию "Полезное"
            status_combo.setEnabled(is_tracked) # Активен, только если отслеживается

            # Связываем состояние чекбокса с активностью комбо-бокса
            checkbox_widget.toggled.connect(status_combo.setEnabled)

            self.app_list_widget.setItem(row, 0, app_name_item)
            self.app_list_widget.setCellWidget(row, 1, checkbox_widget)
            self.app_list_widget.setCellWidget(row, 2, status_combo)
        
        logger.debug(f"Загружено {len(sorted_app_list)} приложений в таблицу настроек.")

    def accept(self):
        logger.info("Сохранение настроек из SettingsDialog...")
        new_tracked_config = {}
        for row in range(self.app_list_widget.rowCount()):
            app_name_item = self.app_list_widget.item(row, 0)
            checkbox_widget = self.app_list_widget.cellWidget(row, 1)
            status_combo = self.app_list_widget.cellWidget(row, 2)

            if app_name_item and checkbox_widget and status_combo:
                app_name = app_name_item.text()
                if checkbox_widget.isChecked():
                    is_useful = status_combo.currentIndex() == 0 # 0 - Полезное, 1 - Неполезное
                    new_tracked_config[app_name] = is_useful
            else:
                logger.warning(f"Пропуск строки {row} в SettingsDialog: не найдены все виджеты.")

        self.main_window.update_tracked_applications_config(new_tracked_config)
        super().accept() # Закрывает диалог со статусом QDialog.Accepted

    def reject(self):
        logger.info("Изменения в SettingsDialog отменены.")
        super().reject() # Закрывает диалог со статусом QDialog.Rejected


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = TimeTrackerApp()
    window.show()
    sys.exit(app.exec_()) 