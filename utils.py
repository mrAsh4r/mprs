#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS Utils Module
Вспомогательные функции и утилиты
"""

import logging
import configparser
import ipaddress
import re
from pathlib import Path

def load_config(config_path):
    """Загрузка конфигурационного файла"""
    config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
    
    # Значения по умолчанию
    config.read_dict({
        'GENERAL': {
            'interface': 'eth0',
            'log_level': 'INFO',
            'max_log_size': '100MB'
        },
        'CAPTURE': {
            'bpf_filter': 'tcp or udp or icmp',
            'promisc_mode': 'true',
            'snaplen': '1500'
        },
        'BLOCKING': {
            'soft_block_duration': '300',
            'hard_block_duration': '3600',
            'max_concurrent_blocks': '1000',
            'whitelist_file': '/etc/mprs/whitelist.txt'
        },
        'TELEGRAM': {
            'enabled': 'false',
            'bot_token': '',
            'chat_id': '',
            'rate_limit': '10'
        },
        'WEB': {
            'enabled': 'true',
            'host': '0.0.0.0',
            'port': '8080',
            'debug': 'false'
        },
        'LOGGING': {
            'events_file': '/var/log/mprs/events.json',
            'blocked_ips_file': '/var/log/mprs/blocked_ips.json',
            'rotate_size': '50MB',
            'rotate_count': '5'
        }
    })
    
    # Попытка загрузить конфигурацию
    config_file = Path(config_path)
    if config_file.exists():
        try:
            config.read(config_path, encoding='utf-8')
            logging.info("Конфигурация загружена из: %s", config_path)
        except Exception as e:
            logging.error("Ошибка загрузки конфигурации: %s", e)
            logging.info("Используются значения по умолчанию")
    else:
        logging.warning("Файл конфигурации не найден: %s", config_path)
        logging.info("Используются значения по умолчанию")
        
        # Пытаемся найти альтернативный путь
        alt_path = Path('config/mprs.conf')
        if alt_path.exists():
            try:
                config.read(str(alt_path), encoding='utf-8')
                logging.info("Конфигурация загружена из альтернативного пути: %s", alt_path)
            except Exception as e:
                logging.error("Ошибка загрузки альтернативной конфигурации: %s", e)
    
    return config

def setup_logging():
    """Настройка системы логирования"""
    # Создаем каталог для логов если не существует
    log_dir = Path('/var/log/mprs')
    if not log_dir.exists():
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Если нет прав на /var/log, используем текущий каталог
            log_dir = Path('./logs')
            log_dir.mkdir(exist_ok=True)
    
    # Настройка форматирования
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Настройка вывода в консоль
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Настройка файлового логгера
    file_handler = logging.FileHandler(
        log_dir / 'mprs.log', 
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    
    # Настройка корневого логгера
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    # Подавляем избыточное логирование от внешних библиотек
    logging.getLogger('scapy').setLevel(logging.WARNING)
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    logging.info("Система логирования настроена")
