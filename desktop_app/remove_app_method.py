def remove_app(self):
    """Удаляет выбранное приложение из списка отслеживаемых"""
    # Получаем выбранный элемент
    selected_items = self.app_list.selectedItems()
    if not selected_items:
        self.status_bar.showMessage("Не выбрано ни одного приложения")
        return
        
    app_name = selected_items[0].text()
    
    # Создаем копию текущего списка отслеживаемых приложений
    new_tracked_config = self.tracked_applications_config.copy()
    
    # Удаляем приложение из списка
    if app_name.lower() in new_tracked_config:
        del new_tracked_config[app_name.lower()]
        self.update_tracked_applications_config(new_tracked_config)
        self.status_bar.showMessage(f"Приложение '{app_name}' удалено из списка отслеживаемых")
        
        # Обновляем список приложений в UI
        self.update_app_list()
    else:
        self.status_bar.showMessage(f"Приложение '{app_name}' не найдено в списке отслеживаемых")
