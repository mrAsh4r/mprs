#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS Event Logger Module
Модуль логирования событий безопасности
"""

import logging
import json
import time
import os
from pathlib import Path
from datetime import datetime
from threading import Lock

class EventLogger:
    """Класс для логирования событий MPRS"""
    
    def __init__(self, config):
        self.config = config
        
        # Пути к файлам логов
        self.events_file = Path(config.get('LOGGING', 'events_file', 
                                         fallback='/var/log/mprs/events.json'))
        self.blocked_ips_file = Path(config.get('LOGGING', 'blocked_ips_file',
                                               fallback='/var/log/mprs/blocked_ips.json'))
        
        # Создаем директории если не существуют
        self.events_file.parent.mkdir(parents=True, exist_ok=True)
        self.blocked_ips_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Блокировки для потокобезопасности
        self.events_lock = Lock()
        self.blocks_lock = Lock()
        
        # Настройки ротации
        self.max_size = self._parse_size(config.get('LOGGING', 'rotate_size', fallback='50MB'))
        self.max_count = config.getint('LOGGING', 'rotate_count', fallback=5)
        
        logging.info("Event logger инициализирован: %s", self.events_file.parent)
    
    def _parse_size(self, size_str):
        """Парсинг размера файла из строки (например, '50MB')"""
        size_str = size_str.upper().strip()
        
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def _rotate_file(self, filepath):
        """Ротация файла логов"""
        try:
            if not filepath.exists():
                return
            
            # Проверяем размер файла
            if filepath.stat().st_size < self.max_size:
                return
            
            # Сдвигаем существующие файлы
            for i in range(self.max_count - 1, 0, -1):
                old_file = Path(f"{filepath}.{i}")
                new_file = Path(f"{filepath}.{i + 1}")
                
                if old_file.exists():
                    if new_file.exists():
                        new_file.unlink()
                    old_file.rename(new_file)
            
            # Переименовываем текущий файл
            rotated_file = Path(f"{filepath}.1")
            if rotated_file.exists():
                rotated_file.unlink()
            filepath.rename(rotated_file)
            
            logging.info("Выполнена ротация файла: %s", filepath)
            
        except Exception as e:
            logging.error("Ошибка ротации файла %s: %s", filepath, e)
    
    def _write_json_line(self, filepath, data, lock):
        """Запись JSON строки в файл"""
        try:
            with lock:
                # Проверяем ротацию
                self._rotate_file(filepath)
                
                # Добавляем timestamp если его нет
                if 'timestamp' not in data:
                    data['timestamp'] = time.time()
                
                # Записываем строку
                with open(filepath, 'a', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, default=str)
                    f.write('\n')
                    
        except Exception as e:
            logging.error("Ошибка записи в файл %s: %s", filepath, e)
    
    def log_event(self, event):
        """Логирование события обнаружения атаки"""
        # Подготавливаем данные события
        log_entry = {
            'event_type': 'attack_detected',
            'timestamp': event['timestamp'],
            'rule_name': event['rule_name'],
            'description': event['description'],
            'src_ip': event['src_ip'],
            'dst_ip': event['dst_ip'],
            'src_port': event.get('src_port'),
            'dst_port': event.get('dst_port'),
            'protocol': event['proto'],
            'action': event['action'],
            'confidence': event['confidence'],
            'datetime': datetime.fromtimestamp(event['timestamp']).isoformat()
        }
        
        # Добавляем HTTP информацию если есть
        if 'packet_info' in event and 'http_info' in event['packet_info']:
            http_info = event['packet_info']['http_info']
            if any(http_info.values()):  # Если есть хоть какая-то HTTP информация
                log_entry['http_info'] = http_info
        
        self._write_json_line(self.events_file, log_entry, self.events_lock)
        logging.debug("Событие записано в лог: %s от %s", event['rule_name'], event['src_ip'])
    
    def log_block(self, ip_addr, block_type, reason, duration):
        """Логирование блокировки IP"""
        log_entry = {
            'event_type': 'ip_blocked',
            'ip_address': ip_addr,
            'block_type': block_type,
            'reason': reason,
            'duration': duration,
            'blocked_until': time.time() + duration,
            'datetime': datetime.now().isoformat()
        }
        
        self._write_json_line(self.blocked_ips_file, log_entry, self.blocks_lock)
        logging.debug("Блокировка записана в лог: %s (%s)", ip_addr, block_type)
    
    def log_unblock(self, ip_addr, reason, block_info):
        """Логирование разблокировки IP"""
        duration_blocked = time.time() - block_info.get('blocked_at', time.time())
        
        log_entry = {
            'event_type': 'ip_unblocked',
            'ip_address': ip_addr,
            'unblock_reason': reason,
            'original_block_type': block_info.get('type', 'unknown'),
            'original_reason': block_info.get('reason', 'unknown'),
            'duration_blocked': int(duration_blocked),
            'datetime': datetime.now().isoformat()
        }
        
        self._write_json_line(self.blocked_ips_file, log_entry, self.blocks_lock)
        logging.debug("Разблокировка записана в лог: %s (%s)", ip_addr, reason)
    
    def get_recent_events(self, limit=100, event_type=None):
        """Получение последних событий"""
        events = []
        
        try:
            if self.events_file.exists():
                with open(self.events_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Читаем события с конца файла
                for line in reversed(lines[-limit*2:]):  # Берем больше строк для фильтрации
                    try:
                        event = json.loads(line.strip())
                        if event_type is None or event.get('event_type') == event_type:
                            events.append(event)
                            if len(events) >= limit:
                                break
                    except json.JSONDecodeError:
                        continue
                
        except Exception as e:
            logging.error("Ошибка чтения событий: %s", e)
        
        return list(reversed(events))  # Возвращаем в хронологическом порядке
    
    def get_recent_blocks(self, limit=50):
        """Получение последних блокировок"""
        blocks = []
        
        try:
            if self.blocked_ips_file.exists():
                with open(self.blocked_ips_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Читаем блокировки с конца файла
                for line in reversed(lines[-limit*2:]):
                    try:
                        block = json.loads(line.strip())
                        blocks.append(block)
                        if len(blocks) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logging.error("Ошибка чтения блокировок: %s", e)
        
        return list(reversed(blocks))
    
    def get_stats(self):
        """Получение статистики логов"""
        try:
            stats = {
                'events_file_size': 0,
                'blocks_file_size': 0,
                'total_events': 0,
                'total_blocks': 0
            }
            
            if self.events_file.exists():
                stats['events_file_size'] = self.events_file.stat().st_size
                with open(self.events_file, 'r', encoding='utf-8') as f:
                    stats['total_events'] = sum(1 for _ in f)
            
            if self.blocked_ips_file.exists():
                stats['blocks_file_size'] = self.blocked_ips_file.stat().st_size
                with open(self.blocked_ips_file, 'r', encoding='utf-8') as f:
                    stats['total_blocks'] = sum(1 for _ in f)
            
            return stats
            
        except Exception as e:
            logging.error("Ошибка получения статистики логов: %s", e)
            return {}
