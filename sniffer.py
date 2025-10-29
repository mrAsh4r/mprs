#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS Packet Sniffer Module
Модуль захвата и предварительной обработки сетевых пакетов
"""

import logging
import time
from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest

class PacketSniffer:
    """Класс для захвата сетевых пакетов"""
    
    def __init__(self, config, analyzer):
        self.config = config
        self.analyzer = analyzer
        self.running = False
        
        # Настройки захвата
        self.interface = config.get('GENERAL', 'interface', fallback='eth0')
        self.bpf_filter = config.get('CAPTURE', 'bpf_filter', fallback='tcp or udp or icmp')
        self.promisc = config.getboolean('CAPTURE', 'promisc_mode', fallback=True)
        self.snaplen = config.getint('CAPTURE', 'snaplen', fallback=1500)
        
        # Проверка доступности интерфейса
        self._validate_interface()
    
    def _validate_interface(self):
        """Проверка доступности сетевого интерфейса"""
        available_interfaces = get_if_list()
        if self.interface not in available_interfaces:
            logging.warning("Интерфейс %s не найден. Доступные: %s", 
                          self.interface, ', '.join(available_interfaces))
            # Пытаемся найти альтернативный интерфейс
            for iface in ['eth0', 'ens33', 'enp0s3', 'wlan0']:
                if iface in available_interfaces:
                    self.interface = iface
                    logging.info("Используем интерфейс: %s", self.interface)
                    break
            else:
                logging.error("Не найден подходящий сетевой интерфейс")
                raise ValueError("No suitable network interface found")
    
    def _extract_packet_info(self, packet):
        """Извлечение информации из пакета"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            packet_info = {
                'timestamp': time.time(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'proto': ip_layer.proto,
                'length': len(packet),
                'src_port': None,
                'dst_port': None,
                'flags': None,
                'payload_len': 0,
                'http_info': {}
            }
            
            # TCP информация
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': tcp_layer.sprintf('%TCP.flags%'),
                    'payload_len': len(tcp_layer.payload) if tcp_layer.payload else 0
                })
                
                # HTTP информация
                if packet.haslayer(HTTPRequest):
                    http_layer = packet[HTTPRequest]
                    packet_info['http_info'] = {
                        'method': http_layer.Method.decode() if http_layer.Method else '',
                        'host': http_layer.Host.decode() if http_layer.Host else '',
                        'uri': http_layer.Path.decode() if http_layer.Path else '',
                        'user_agent': http_layer.User_Agent.decode() if http_layer.User_Agent else ''
                    }
            
            # UDP информация
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'payload_len': len(udp_layer.payload) if udp_layer.payload else 0
                })
            
            # ICMP информация
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_info.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code
                })
            
            return packet_info
            
        except Exception as e:
            logging.debug("Ошибка обработки пакета: %s", e)
            return None
    
    def _packet_handler(self, packet):
        """Обработчик захваченных пакетов"""
        if not self.running:
            return
        
        packet_info = self._extract_packet_info(packet)
        if packet_info:
            # Передаем пакет анализатору
            self.analyzer.process_packet(packet_info)
    
    def start(self):
        """Запуск захвата пакетов"""
        self.running = True
        logging.info("Запуск захвата пакетов на интерфейсе %s с фильтром: %s", 
                    self.interface, self.bpf_filter)
        
        try:
            # Отключаем verbose режим Scapy
            conf.verb = 0
            
            # Запуск захвата пакетов
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=0,  # Не сохранять пакеты в памяти
                stop_filter=lambda x: not self.running
            )
            
        except PermissionError:
            logging.error("Недостаточно прав для захвата пакетов. Запустите с правами root.")
            raise
        except Exception as e:
            logging.error("Ошибка захвата пакетов: %s", e)
            raise
    
    def stop(self):
        """Остановка захвата пакетов"""
        logging.info("Остановка захвата пакетов...")
        self.running = False
