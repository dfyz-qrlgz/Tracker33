import requests
import json
from typing import Dict, Optional
import logging
from datetime import datetime, timedelta
import jwt
from pathlib import Path
import os

log_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "tracker.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("TimeTracker")

class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.token = None
        self.token_expires = None
        self.refresh_token = None
        self.config_dir = Path.home() / '.timetracker'
        self.config_dir.mkdir(exist_ok=True)
        self.token_file = self.config_dir / 'token.json'
        self.load_token()

    def load_token(self):
        """Загрузка сохраненного токена"""
        if self.token_file.exists():
            try:
                with open(self.token_file, 'r') as f:
                    data = json.load(f)
                    self.token = data.get('token')
                    self.refresh_token = data.get('refresh_token')
                    self.token_expires = datetime.fromisoformat(data.get('expires'))
            except Exception as e:
                logger.error(f"Ошибка загрузки токена: {e}")
                self.token = None
                self.refresh_token = None
                self.token_expires = None

    def save_token(self):
        """Сохранение токена"""
        if self.token and self.token_expires:
            try:
                with open(self.token_file, 'w') as f:
                    json.dump({
                        'token': self.token,
                        'refresh_token': self.refresh_token,
                        'expires': self.token_expires.isoformat()
                    }, f)
            except Exception as e:
                logger.error(f"Ошибка сохранения токена: {e}")

    def authenticate(self, username: str, password: str) -> bool:
        """Аутентификация на сервере"""
        try:
            response = requests.post(
                f"{self.base_url}/api/token/",
                json={
                    'username': username,
                    'password': password
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('access')
                self.refresh_token = data.get('refresh')
                # Декодируем токен для получения времени истечения
                try:
                    token_data = jwt.decode(self.token, options={"verify_signature": False})
                    exp_timestamp = token_data.get('exp')
                    if exp_timestamp:
                        self.token_expires = datetime.fromtimestamp(exp_timestamp)
                    else:
                        self.token_expires = datetime.now() + timedelta(minutes=60)  # Ставим больше время на всякий случай
                except Exception as e:
                    logger.warning(f"Не удалось декодировать токен: {e}")
                    self.token_expires = datetime.now() + timedelta(minutes=60)
                
                logger.info(f"Токен после логина: {self.token[:20]}... действителен до {self.token_expires}")
                self.save_token()
                return True
            else:
                logger.error(f"Ошибка аутентификации: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Ошибка при аутентификации: {e}")
            return False

    def refresh_auth_token(self) -> bool:
        """Обновление токена"""
        if not self.refresh_token:
            return False
            
        try:
            response = requests.post(
                f"{self.base_url}/api/token/refresh/",
                json={'refresh': self.refresh_token}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('access')
                # Декодируем токен для получения времени истечения
                try:
                    token_data = jwt.decode(self.token, options={"verify_signature": False})
                    exp_timestamp = token_data.get('exp')
                    if exp_timestamp:
                        self.token_expires = datetime.fromtimestamp(exp_timestamp)
                    else:
                        self.token_expires = datetime.now() + timedelta(minutes=60)
                except Exception as e:
                    logger.warning(f"Не удалось декодировать токен: {e}")
                    self.token_expires = datetime.now() + timedelta(minutes=60)
                
                logger.info(f"Токен обновлен: {self.token[:20]}... действителен до {self.token_expires}")
                self.save_token()
                return True
            else:
                logger.error(f"Ошибка обновления токена: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Ошибка при обновлении токена: {e}")
            return False

    def is_token_valid(self) -> bool:
        """Проверка валидности токена"""
        if not self.token or not self.token_expires:
            return False
        return datetime.now() < self.token_expires

    def get_headers(self) -> Dict[str, str]:
        """Получение заголовков для запросов"""
        if not self.is_token_valid():
            if not self.refresh_auth_token():
                return {}
        # Используем формат Bearer для JWT токенов
        headers = {'Authorization': f'Bearer {self.token}'}
        logger.info(f"Используем заголовок: {headers}")
        return headers

    def send_activity(self, activity_data: Dict) -> bool:
        """Отправка данных об активности"""
        try:
            headers = self.get_headers()
            logger.info(f"Заголовки для запроса: {headers}")
            # Проверяем, содержит ли base_url уже /api на конце
            api_prefix = '/api' if not self.base_url.endswith('/api') else ''
            response = requests.post(
                f"{self.base_url}{api_prefix}/activities/",
                json=activity_data,
                headers=headers
            )
            logger.info(f"Ответ сервера: {response.status_code} {response.text}")
            return response.status_code == 201
        except Exception as e:
            logger.error(f"Ошибка отправки активности: {e}")
            return False

    def get_user_info(self) -> Optional[Dict]:
        """Получение информации о пользователе (заглушка)"""
        logger.info("Вызов get_user_info пропущен: ручка /api/user/ не реализована на сервере.")
        return None

    def logout(self):
        """Выход из системы"""
        self.token = None
        self.refresh_token = None
        self.token_expires = None
        if self.token_file.exists():
            try:
                os.remove(self.token_file)
            except Exception as e:
                logger.error(f"Ошибка удаления файла токена: {e}") 