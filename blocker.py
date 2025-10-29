#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS Traffic Blocker Module
Модуль блокировки трафика через iptables/nftables
"""

import logging
import time
import subprocess
import threading
import ipaddress
from pathlib import Path
from collections import defaultdict

class TrafficBlocker:
    """Класс для блокировки трафика"""
    
    def __init__(self, config, event_logger):
        self.config = config
        self.event_logger = event_logger
        
        # Настройки блокировки
        self.soft_duration = config.getint('BLOCKING', 'soft_block_duration', fallback=300)
        self.hard_duration = config.getint('BLOCKING', 'hard_block_duration', fallback=3600)
        self.max_blocks = config.getint('BLOCKING', 'max_concurrent_blocks', fallback=1000)
        
        # Хранение заблокированных IP
        self.blocked_ips = {}  # ip -> {'type': soft/hard, 'until': timestamp, 'reason': rule_name}
        self.block_lock = threading.Lock()
        
        # Whitelist
        self.whitelist = set()
        
        # Проверка доступности iptables
        self._check_iptables()
        
        # Запуск потока очистки
        self._start_cleanup_thread()
    
    def _check_iptables(self):
        """Проверка доступности iptables"""
        try:
            result = subprocess.run(['iptables', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logging.info("iptables доступен: %s", result.stdout.strip())
            else:
                logging.error("iptables недоступен")
                raise RuntimeError("iptables not available")
        except Exception as e:
            logging.error("Ошибка проверки iptables: %s", e)
            raise
    
    def load_whitelist(self):
        """Загрузка whitelist из файла"""
        whitelist_file = Path(self.config.get('BLOCKING', 'whitelist_file', 
                                            fallback='/etc/mprs/whitelist.txt'))
        
        if not whitelist_file.exists():
            whitelist_file = Path('config/whitelist.txt')
        
        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            # Проверяем, это IP или подсеть
                            network = ipaddress.ip_network(line, strict=False)
                            self.whitelist.add(str(network))
                        except ValueError as e:
                            logging.warning("Некорректная запись в whitelist: %s (%s)", line, e)
            
            logging.info("Загружено %d записей в whitelist", len(self.whitelist))
            
        except Exception as e:
            logging.error("Ошибка загрузки whitelist: %s", e)
    
    def _is_whitelisted(self, ip_addr):
        """Проверка IP на whitelist"""
        try:
            ip = ipaddress.ip_address(ip_addr)
            
            for whitelist_entry in self.whitelist:
                network = ipaddress.ip_network(whitelist_entry, strict=False)
                if ip in network:
                    return True
            
            return False
            
        except ValueError:
            logging.debug("Некорректный IP адрес для проверки whitelist: %s", ip_addr)
            return False
    
    def _execute_iptables_command(self, action, ip_addr):
        """Выполнение команды iptables"""
        try:
            if action == 'block':
                cmd = ['iptables', '-I', 'INPUT', '1', '-s', ip_addr, '-j', 'DROP']
            elif action == 'unblock':
                cmd = ['iptables', '-D', 'INPUT', '-s', ip_addr, '-j', 'DROP']
            else:
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                logging.debug("Команда iptables выполнена: %s", ' '.join(cmd))
                return True
            else:
                logging.error("Ошибка выполнения iptables: %s", result.stderr)
                return False
                
        except Exception as e:
            logging.error("Ошибка выполнения команды iptables: %s", e)
            return False
    
    def block_ip(self, ip_addr, block_type='soft_block', reason='unknown'):
        """Блокировка IP адреса"""
        with self.block_lock:
            # Проверка whitelist
            if self._is_whitelisted(ip_addr):
                logging.info("IP %s в whitelist, блокировка пропущена", ip_addr)
                return False
            
            # Проверка лимита блокировок
            if len(self.blocked_ips) >= self.max_blocks:
                logging.warning("Достигнут лимит блокировок (%d), пропуск %s", 
                              self.max_blocks, ip_addr)
                return False
            
            # Проверка, уже ли заблокирован
            if ip_addr in self.blocked_ips:
                existing_block = self.blocked_ips[ip_addr]
                
                # Если это повторная атака в течение soft block - переводим в hard
                if existing_block['type'] == 'soft_block' and block_type == 'soft_block':
                    logging.info("Повторная атака от %s, переход в hard block", ip_addr)
                    block_type = 'hard_block'
                    duration = self.hard_duration
                else:
                    logging.debug("IP %s уже заблокирован (%s)", ip_addr, existing_block['type'])
                    return True
            else:
                duration = self.soft_duration if block_type == 'soft_block' else self.hard_duration
            
            # Выполняем блокировку
            if self._execute_iptables_command('block', ip_addr):
                until_time = time.time() + duration
                self.blocked_ips[ip_addr] = {
                    'type': block_type,
                    'until': until_time,
                    'reason': reason,
                    'blocked_at': time.time()
                }
                
                # Логируем блокировку
                self.event_logger.log_block(ip_addr, block_type, reason, duration)
                
                # Планируем автоматическую разблокировку для soft block
                if block_type == 'soft_block':
                    timer = threading.Timer(duration, self._auto_unblock, args=[ip_addr])
                    timer.start()
                
                logging.info("Заблокирован IP %s (%s, %ds, причина: %s)", 
                           ip_addr, block_type, duration, reason)
                return True
            else:
                logging.error("Не удалось заблокировать IP %s", ip_addr)
                return False
    
    def unblock_ip(self, ip_addr, reason='manual'):
        """Разблокировка IP адреса"""
        with self.block_lock:
            if ip_addr not in self.blocked_ips:
                logging.warning("IP %s не найден в списке заблокированных", ip_addr)
                return False
            
            if self._execute_iptables_command('unblock', ip_addr):
                block_info = self.blocked_ips.pop(ip_addr)
                
                # Логируем разблокировку
                self.event_logger.log_unblock(ip_addr, reason, block_info)
                
                logging.info("Разблокирован IP %s (причина: %s)", ip_addr, reason)
                return True
            else:
                logging.error("Не удалось разблокировать IP %s", ip_addr)
                return False
    
    def _auto_unblock(self, ip_addr):
        """Автоматическая разблокировка по таймеру"""
        self.unblock_ip(ip_addr, 'auto_timeout')
    
    def _cleanup_expired_blocks(self):
        """Очистка истекших блокировок"""
        current_time = time.time()
        expired_ips = []
        
        with self.block_lock:
            for ip_addr, block_info in self.blocked_ips.items():
                if current_time >= block_info['until']:
                    expired_ips.append(ip_addr)
        
        # Разблокируем истекшие
        for ip_addr in expired_ips:
            self.unblock_ip(ip_addr, 'expired')
    
    def _start_cleanup_thread(self):
        """Запуск потока очистки истекших блокировок"""
        def cleanup_worker():
            while True:
                try:
                    self._cleanup_expired_blocks()
                    time.sleep(60)  # Проверяем каждую минуту
                except Exception as e:
                    logging.error("Ошибка в потоке очистки блокировок: %s", e)
                    time.sleep(60)
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        logging.info("Запущен поток очистки истекших блокировок")
    
    def get_blocked_ips(self):
        """Получение списка заблокированных IP"""
        with self.block_lock:
            return dict(self.blocked_ips)
    
    def get_block_stats(self):
        """Получение статистики блокировок"""
        with self.block_lock:
            total = len(self.blocked_ips)
            soft_blocks = sum(1 for b in self.blocked_ips.values() if b['type'] == 'soft_block')
            hard_blocks = total - soft_blocks
            
            return {
                'total_blocked': total,
                'soft_blocks': soft_blocks,
                'hard_blocks': hard_blocks,
                'max_blocks': self.max_blocks
            }
    
    def cleanup(self):
        """Очистка всех блокировок при завершении"""
        logging.info("Очистка всех активных блокировок...")
        
        blocked_list = list(self.blocked_ips.keys())
        for ip_addr in blocked_list:
            self.unblock_ip(ip_addr, 'system_shutdown')
        
        logging.info("Очистка блокировок завершена")
