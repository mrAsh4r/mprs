#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS Alert Notifier Module
Модуль отправки уведомлений о событиях безопасности
"""

import logging
import time
import requests
import threading
from collections import deque
from datetime import datetime

class AlertNotifier:
    """Класс для отправки уведомлений"""
    
    def __init__(self, config, event_logger):
        self.config = config
        self.event_logger = event_logger
        
        # Настройки Telegram
        self.telegram_enabled = config.getboolean('TELEGRAM', 'enabled', fallback=False)
        self.bot_token = config.get('TELEGRAM', 'bot_token', fallback='')
        self.chat_id = config.get('TELEGRAM', 'chat_id', fallback='')
        self.rate_limit = config.getint('TELEGRAM', 'rate_limit', fallback=10)
        
        # Rate limiting для уведомлений
        self.message_queue = deque()
        self.last_notifications = {}  # rule_name -> timestamp
        
        # Проверка настроек Telegram
        if self.telegram_enabled:
            self._validate_telegram_config()
            logging.info("Telegram уведомления включены (rate limit: %d/мин)", self.rate_limit)
        else:
            logging.info("Telegram уведомления отключены")
    
    def _validate_telegram_config(self):
        """Проверка настроек Telegram"""
        if not self.bot_token or self.bot_token == 'YOUR_BOT_TOKEN':
            logging.warning("Не указан bot_token для Telegram")
            self.telegram_enabled = False
            return
        
        if not self.chat_id or self.chat_id == 'YOUR_CHAT_ID':
            logging.warning("Не указан chat_id для Telegram")
            self.telegram_enabled = False
            return
        
        # Тестовая отправка
        try:
            self._send_telegram_message("🔐 MPRS система запущена и готова к работе")
            logging.info("Тестовое уведомление Telegram отправлено успешно")
        except Exception as e:
            logging.error("Ошибка отправки тестового уведомления: %s", e)
    
    def _send_telegram_message(self, message):
        """Отправка сообщения в Telegram"""
        if not self.telegram_enabled:
            return False
        
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        data = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True
        }
        
        try:
            response = requests.post(url, json=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if result.get('ok'):
                return True
            else:
                logging.error("Telegram API ошибка: %s", result.get('description'))
                return False
                
        except requests.exceptions.RequestException as e:
            logging.error("Ошибка отправки Telegram сообщения: %s", e)
            return False
    
    def _format_alert_message(self, event):
        """Форматирование сообщения о событии"""
        timestamp = datetime.fromtimestamp(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        
        # Эмодзи для разных типов атак
        emoji_map = {
            'ssh_bruteforce': '🔑',
            'http_bad_ua': '🌐',
            'syn_flood': '💥',
            'port_scan': '🔍',
            'icmp_flood': '📡',
            'dns_amplification': '🌐',
            'http_flood': '🌊',
            'web_shells': '🐚'
        }
        
        emoji = emoji_map.get(event['rule_name'], '⚠️')
        
        message = f"{emoji} <b>MPRS Alert</b>\n\n"
        message += f"📊 <b>Правило:</b> {event['rule_name']}\n"
        message += f"📝 <b>Описание:</b> {event['description']}\n"
        message += f"🌐 <b>IP атакующего:</b> <code>{event['src_ip']}</code>\n"
        message += f"🎯 <b>Цель:</b> {event['dst_ip']}"
        
        if event.get('dst_port'):
            message += f":{event['dst_port']}"
        
        message += f"\n⏰ <b>Время:</b> {timestamp}\n"
        message += f"🔒 <b>Действие:</b> {event['action']}"
        
        # Дополнительная информация для HTTP атак
        if 'http_info' in event.get('packet_info', {}):
            http_info = event['packet_info']['http_info']
            if http_info.get('user_agent'):
                ua = http_info['user_agent'][:50] + '...' if len(http_info['user_agent']) > 50 else http_info['user_agent']
                message += f"\n🔍 <b>User-Agent:</b> <code>{ua}</code>"
        
        return message
    
    def _should_send_notification(self, event):
        """Проверка, нужно ли отправлять уведомление (rate limiting)"""
        rule_name = event['rule_name']
        current_time = time.time()
        
        # Проверка rate limit по правилу (не чаще раза в минуту для одного правила)
        if rule_name in self.last_notifications:
            if current_time - self.last_notifications[rule_name] < 60:
                return False
        
        # Проверка общего rate limit
        # Очищаем старые сообщения из очереди
        while self.message_queue and self.message_queue[0] < current_time - 60:
            self.message_queue.popleft()
        
        # Проверяем лимит сообщений в минуту
        if len(self.message_queue) >= self.rate_limit:
            return False
        
        return True
    
    def send_alert(self, event):
        """Отправка уведомления о событии"""
        try:
            # Проверяем rate limiting
            if not self._should_send_notification(event):
                logging.debug("Уведомление пропущено из-за rate limiting: %s", event['rule_name'])
                return
            
            # Обновляем счетчики
            current_time = time.time()
            self.last_notifications[event['rule_name']] = current_time
            self.message_queue.append(current_time)
            
            # Отправляем уведомление в Telegram
            if self.telegram_enabled:
                message = self._format_alert_message(event)
                
                # Отправляем в отдельном потоке, чтобы не блокировать основной поток
                def send_async():
                    success = self._send_telegram_message(message)
                    if success:
                        logging.info("Telegram уведомление отправлено: %s от %s", 
                                   event['rule_name'], event['src_ip'])
                    else:
                        logging.error("Не удалось отправить Telegram уведомление")
                
                threading.Thread(target=send_async, daemon=True).start()
            
        except Exception as e:
            logging.error("Ошибка отправки уведомления: %s", e)
    
    def send_system_notification(self, message, level='info'):
        """Отправка системного уведомления"""
        try:
            if self.telegram_enabled:
                emoji_map = {
                    'info': 'ℹ️',
                    'warning': '⚠️',
                    'error': '❌',
                    'success': '✅'
                }
                
                emoji = emoji_map.get(level, 'ℹ️')
                formatted_message = f"{emoji} <b>MPRS System</b>\n\n{message}"
                
                threading.Thread(
                    target=self._send_telegram_message, 
                    args=[formatted_message], 
                    daemon=True
                ).start()
                
        except Exception as e:
            logging.error("Ошибка отправки системного уведомления: %s", e)
    
    def get_notification_stats(self):
        """Получение статистики уведомлений"""
        current_time = time.time()
        
        # Очищаем старые сообщения
        while self.message_queue and self.message_queue[0] < current_time - 60:
            self.message_queue.popleft()
        
        return {
            'telegram_enabled': self.telegram_enabled,
            'messages_last_minute': len(self.message_queue),
            'rate_limit': self.rate_limit,
            'total_rules_notified': len(self.last_notifications)
        }
