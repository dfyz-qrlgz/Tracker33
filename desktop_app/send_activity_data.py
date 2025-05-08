def send_activity_data(self):
    """Отправляет накопленные данные активности на сервер."""
    if self.activity_queue.empty():
        logger.debug("Очередь активностей пуста, нечего отправлять.")
        return
        
    # Получаем API URL из конфигурации
    api_url = self.config.get('Credentials', 'api_base_url', fallback='http://localhost:8000/api/') + 'activities/'
    auth_token = self.config.get('Credentials', 'auth_token', fallback=None)
    
    if not auth_token:
        logger.warning("Отсутствует токен авторизации. Отправка данных невозможна.")
        return
        
    # Заголовки для запроса
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth_token}'
    }
    
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
            api_payload = {
                'app_name': activity_dict.get('app_name', ''),
                'window_title': activity_dict.get('window_title', ''),
                'start_time': activity_dict.get('start_time_iso_utc', ''),
                'end_time': activity_dict.get('end_time_iso_utc', ''),
                'duration_seconds': activity_dict.get('duration_seconds', 0),
                'is_useful': activity_dict.get('is_useful', False),
                'machine_id': activity_dict.get('machine_id', self.machine_id),
                'user_id': activity_dict.get('user_id', self.user_id),
                'event_type': activity_dict.get('event_type', 'unknown')
            }
            activities_to_send_payload.append(api_payload)
        
        if not activities_to_send_payload:
            logger.debug("Нет данных для отправки после фильтрации.")
            return
            
        # Отправляем данные на сервер
        logger.info(f"Отправка {len(activities_to_send_payload)} записей активности на сервер.")
        response = self.session.post(api_url, json=activities_to_send_payload, headers=headers, timeout=30)
        
        if response.status_code == 200 or response.status_code == 201:
            logger.info(f"Успешно отправлено {len(activities_to_send_payload)} записей активности.")
            self.status_bar.showMessage(f"Отправлено {len(activities_to_send_payload)} записей активности.")
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
