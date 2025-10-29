#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS Traffic Analyzer Module
Модуль анализа трафика и применения правил обнаружения
"""

import logging
import time
import re
import ipaddress
from collections import defaultdict, deque
from pathlib import Path
import yaml

class TrafficAnalyzer:
    """Класс для анализа трафика и обнаружения атак"""
    
    def __init__(self, config, blocker, notifier, event_logger):
        self.config = config
        self.blocker = blocker
        self.notifier = notifier
        self.event_logger = event_logger
        
        # Хранилище счетчиков для rate-based правил
        self.rate_counters = defaultdict(lambda: defaultdict(deque))
        self.port_scan_counters = defaultdict(set)
        
        # Загрузка правил
        self.rules = self._load_rules()
        logging.info("Загружено %d правил обнаружения", len(self.rules))
    
    def _load_rules(self):
        """Загрузка правил из YAML файла"""
        rules_file = Path('/etc/mprs/rules.yaml')
        if not rules_file.exists():
            rules_file = Path('config/rules.yaml')
        
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)
            logging.info("Правила загружены из: %s", rules_file)
            return rules
        except Exception as e:
            logging.error("Ошибка загрузки правил: %s", e)
            return {}
    
    def _match_ports(self, packet_port, rule_ports):
        """Проверка соответствия порта правилу"""
        if isinstance(rule_ports, list):
            return packet_port in rule_ports
        elif isinstance(rule_ports, int):
            return packet_port == rule_ports
        return False
    
    def _match_protocol(self, packet_proto, rule_proto):
        """Проверка соответствия протокола правилу"""
        proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
        
        if isinstance(rule_proto, str):
            return packet_proto == proto_map.get(rule_proto.lower())
        elif isinstance(rule_proto, int):
            return packet_proto == rule_proto
        return False
    
    def _check_signature_rule(self, packet_info, rule_name, rule):
        """Проверка сигнатурного правила"""
        try:
            # Проверка протокола
            if 'proto' in rule and not self._match_protocol(packet_info['proto'], rule['proto']):
                return False
            
            # Проверка портов
            if 'dst_port' in rule and packet_info.get('dst_port'):
                if not self._match_ports(packet_info['dst_port'], rule['dst_port']):
                    return False
            
            # Проверка User-Agent
            if 'regex' in rule and packet_info.get('http_info', {}).get('user_agent'):
                user_agent = packet_info['http_info']['user_agent']
                if re.search(rule['regex'], user_agent, re.IGNORECASE):
                    return True
            
            # Проверка URI
            if 'uri_regex' in rule and packet_info.get('http_info', {}).get('uri'):
                uri = packet_info['http_info']['uri']
                if re.search(rule['uri_regex'], uri, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception as e:
            logging.debug("Ошибка проверки сигнатурного правила %s: %s", rule_name, e)
            return False
    
    def _check_rate_rule(self, packet_info, rule_name, rule):
        """Проверка rate-based правила"""
        try:
            src_ip = packet_info['src_ip']
            dst_ip = packet_info['dst_ip']
            current_time = packet_info['timestamp']
            window = rule.get('window', 60)
            threshold = rule.get('threshold', 10)
            
            # ИСПРАВЛЕНИЕ: Игнорируем исходящий трафик с локального сервера
            if src_ip == dst_ip:  # Локальный трафик
                return False
                
            # Получаем локальный IP сервера
            try:
                import socket
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                
                # Игнорируем исходящие соединения от сервера
                if src_ip == local_ip:
                    return False
                    
            except:
                pass
            
            # Проверка протокола
            if 'proto' in rule and not self._match_protocol(packet_info['proto'], rule['proto']):
                return False
            
            # Проверка портов
            if 'dst_port' in rule and packet_info.get('dst_port'):
                if not self._match_ports(packet_info['dst_port'], rule['dst_port']):
                    return False
            
            # Проверка TCP флагов
            if 'flags' in rule and packet_info.get('flags'):
                if rule['flags'] not in packet_info['flags']:
                    return False
            
            # Специальная обработка port scan
            if rule.get('unique_ports', False):
                dst_port = packet_info.get('dst_port')
                if dst_port:
                    # ИСПРАВЛЕНИЕ: Только входящие SYN пакеты считаем сканированием
                    # Проверяем, что это входящий трафик
                    try:
                        import ipaddress
                        src_net = ipaddress.ip_address(src_ip)
                        dst_net = ipaddress.ip_address(dst_ip)
                        
                        # Если источник - внешний IP, а получатель - локальный
                        if not src_net.is_private and (dst_net.is_private or dst_ip == local_ip):
                            # Добавляем порт в набор для данного IP
                            self.port_scan_counters[src_ip].add(dst_port)
                            
                            # Очищаем старые записи (простая реализация)
                            if len(self.port_scan_counters[src_ip]) >= threshold:
                                unique_ports = len(self.port_scan_counters[src_ip])
                                if unique_ports >= threshold:
                                    return True
                    except:
                        pass
                        
                return False
            
            # Обычная rate проверка
            counter_key = f"{rule_name}_{src_ip}"
            counter = self.rate_counters[counter_key][rule_name]
            
            # Добавляем текущий timestamp
            counter.append(current_time)
            
            # Удаляем старые записи
            while counter and counter[0] < current_time - window:
                counter.popleft()
            
            # Проверяем превышение лимита
            return len(counter) >= threshold
            
        except Exception as e:
            logging.debug("Ошибка проверки rate правила %s: %s", rule_name, e)
            return False
    
    def _create_event(self, packet_info, rule_name, rule):
        """Создание события обнаружения атаки"""
        return {
            'timestamp': packet_info['timestamp'],
            'rule_name': rule_name,
            'description': rule.get('description', 'Unknown attack'),
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'proto': packet_info['proto'],
            'action': rule.get('action', 'log'),
            'confidence': 'high' if rule['type'] == 'signature' else 'medium',
            'packet_info': packet_info
        }
    
    def process_packet(self, packet_info):
        """Обработка пакета - применение всех правил"""
        try:
            for rule_name, rule in self.rules.items():
                rule_type = rule.get('type', 'signature')
                detected = False
                
                if rule_type == 'signature':
                    detected = self._check_signature_rule(packet_info, rule_name, rule)
                elif rule_type == 'rate':
                    detected = self._check_rate_rule(packet_info, rule_name, rule)
                
                if detected:
                    # Создаем событие
                    event = self._create_event(packet_info, rule_name, rule)
                    
                    # Логируем событие
                    self.event_logger.log_event(event)
                    
                    # Выполняем действие
                    action = rule.get('action', 'log')
                    if action in ['soft_block', 'hard_block']:
                        success = self.blocker.block_ip(
                            packet_info['src_ip'], 
                            action, 
                            rule_name
                        )
                        if success:
                            # Отправляем уведомление
                            self.notifier.send_alert(event)
                    
                    logging.info("Обнаружена атака: %s от %s (%s)", 
                               rule_name, packet_info['src_ip'], 
                               rule.get('description', 'Unknown attack'))
        
        except Exception as e:
            logging.debug("Ошибка обработки пакета: %s", e)
    
    def cleanup_counters(self):
        """Очистка старых счетчиков (вызывается периодически)"""
        current_time = time.time()
        
        # Очистка rate counters
        for counter_dict in self.rate_counters.values():
            for rule_name, counter in counter_dict.items():
                while counter and counter[0] < current_time - 300:  # 5 минут
                    counter.popleft()
        
        # Очистка port scan counters (каждые 30 минут)
        if hasattr(self, '_last_cleanup'):
            if current_time - self._last_cleanup > 1800:  # 30 минут
                self.port_scan_counters.clear()
                self._last_cleanup = current_time
        else:
            self._last_cleanup = current_time
