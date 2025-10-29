#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS - Minimal Prevention & Response System
Главный модуль запуска системы
"""

import sys
import os
import signal
import threading
import time
import logging
from pathlib import Path

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sniffer import PacketSniffer
from analyzer import TrafficAnalyzer
from blocker import TrafficBlocker
from notifier import AlertNotifier
from web_ui import WebInterface
from logger import EventLogger
from utils import load_config, setup_logging

class MPRSCore:
    """Основной класс MPRS системы"""
    
    def __init__(self, config_path='/etc/mprs/mprs.conf'):
        self.config = load_config(config_path)
        self.running = False
        
        # Инициализация компонентов
        self.event_logger = EventLogger(self.config)
        self.blocker = TrafficBlocker(self.config, self.event_logger)
        self.notifier = AlertNotifier(self.config, self.event_logger)
        self.analyzer = TrafficAnalyzer(self.config, self.blocker, self.notifier, self.event_logger)
        self.sniffer = PacketSniffer(self.config, self.analyzer)
        
        if self.config.getboolean('WEB', 'enabled', fallback=True):
            self.web_interface = WebInterface(self.config, self.event_logger, self.blocker)
        else:
            self.web_interface = None
    
    def start(self):
        """Запуск всех компонентов системы"""
        try:
            logging.info("Запуск MPRS системы...")
            self.running = True
            
            # Загрузка whitelist
            self.blocker.load_whitelist()
            
            # Запуск веб-интерфейса в отдельном потоке
            if self.web_interface:
                web_thread = threading.Thread(target=self.web_interface.run, daemon=True)
                web_thread.start()
                logging.info("Веб-интерфейс запущен на порту %s", 
                           self.config.get('WEB', 'port', fallback='8080'))
            
            # Запуск сниффера (блокирующий вызов)
            logging.info("Начинаем захват пакетов на интерфейсе %s", 
                        self.config.get('CAPTURE', 'interface', fallback='eth0'))
            self.sniffer.start()
            
        except KeyboardInterrupt:
            logging.info("Получен сигнал прерывания")
        except Exception as e:
            logging.error("Ошибка запуска системы: %s", e)
        finally:
            self.stop()
    
    def stop(self):
        """Остановка всех компонентов системы"""
        logging.info("Остановка MPRS системы...")
        self.running = False
        
        if hasattr(self, 'sniffer'):
            self.sniffer.stop()
        
        if hasattr(self, 'blocker'):
            self.blocker.cleanup()
        
        logging.info("MPRS система остановлена")

def signal_handler(signum, frame):
    """Обработчик сигналов завершения"""
    logging.info("Получен сигнал %s, завершение работы...", signum)
    sys.exit(0)

def main():
    """Главная функция"""
    # Проверка прав root
    if os.geteuid() != 0:
        print("ОШИБКА: Для захвата пакетов требуются права root")
        print("Запустите с sudo: sudo python3 main.py")
        sys.exit(1)
    
    # Настройка логирования
    setup_logging()
    
    # Регистрация обработчиков сигналов
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Создание и запуск системы
    try:
        mprs = MPRSCore()
        mprs.start()
    except Exception as e:
        logging.error("Критическая ошибка: %s", e)
        sys.exit(1)

if __name__ == '__main__':
    main()
