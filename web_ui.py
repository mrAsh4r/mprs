#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS Web UI Module
Расширенный веб-интерфейс для управления и мониторинга MPRS
"""

import logging
import json
import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string
from collections import defaultdict, Counter

class WebInterface:
    """Класс веб-интерфейса MPRS"""
    
    def __init__(self, config, event_logger, blocker):
        self.config = config
        self.event_logger = event_logger
        self.blocker = blocker
        
        # Настройки Flask
        self.app = Flask(__name__)
        self.host = config.get('WEB', 'host', fallback='0.0.0.0')
        self.port = config.getint('WEB', 'port', fallback=8080)
        self.debug = config.getboolean('WEB', 'debug', fallback=False)
        
        # Регистрация маршрутов
        self._register_routes()
        
        logging.info("Веб-интерфейс инициализирован: http://%s:%d", self.host, self.port)
    
    def _register_routes(self):
        """Регистрация маршрутов Flask"""
        
        @self.app.route('/')
        def index():
            """Главная страница"""
            return render_template_string(HTML_TEMPLATE)
        
        @self.app.route('/api/events')
        def get_events():
            """API: получение событий с фильтрацией и сортировкой"""
            try:
                limit = request.args.get('limit', 100, type=int)
                event_type = request.args.get('type', None)
                search_ip = request.args.get('search_ip', None)
                rule_filter = request.args.get('rule', None)
                sort_by = request.args.get('sort', 'timestamp')
                sort_order = request.args.get('order', 'desc')
                
                events = self.event_logger.get_recent_events(limit * 2, event_type)
                
                # Фильтрация по IP
                if search_ip:
                    events = [e for e in events if search_ip in e.get('src_ip', '')]
                
                # Фильтрация по правилу
                if rule_filter:
                    events = [e for e in events if e.get('rule_name') == rule_filter]
                
                # Сортировка
                if sort_by in ['timestamp', 'rule_name', 'src_ip']:
                    reverse = (sort_order == 'desc')
                    events.sort(key=lambda x: x.get(sort_by, ''), reverse=reverse)
                
                # Обрезаем до нужного лимита
                events = events[:limit]
                
                return jsonify({
                    'success': True,
                    'events': events,
                    'count': len(events),
                    'filters': {
                        'search_ip': search_ip,
                        'rule_filter': rule_filter,
                        'sort_by': sort_by,
                        'sort_order': sort_order
                    }
                })
            except Exception as e:
                logging.error("Ошибка получения событий: %s", e)
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/blocked')
        def get_blocked():
            """API: получение заблокированных IP с фильтрацией"""
            try:
                block_type = request.args.get('type', None)  # soft/hard
                search_ip = request.args.get('search_ip', None)
                
                blocked_ips = self.blocker.get_blocked_ips()
                block_stats = self.blocker.get_block_stats()
                
                # Преобразуем данные для JSON
                blocked_list = []
                current_time = datetime.now().timestamp()
                
                for ip, info in blocked_ips.items():
                    # Фильтрация по типу
                    if block_type and info['type'] != block_type:
                        continue
                    
                    # Фильтрация по IP
                    if search_ip and search_ip not in ip:
                        continue
                    
                    blocked_list.append({
                        'ip': ip,
                        'type': info['type'],
                        'reason': info['reason'],
                        'blocked_at': info['blocked_at'],
                        'until': info['until'],
                        'remaining': max(0, int(info['until'] - current_time)),
                        'duration': int(current_time - info['blocked_at'])
                    })
                
                # Сортировка по времени блокировки (новые сначала)
                blocked_list.sort(key=lambda x: x['blocked_at'], reverse=True)
                
                return jsonify({
                    'success': True,
                    'blocked_ips': blocked_list,
                    'stats': block_stats
                })
            except Exception as e:
                logging.error("Ошибка получения заблокированных IP: %s", e)
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/unblock', methods=['POST'])
        def unblock_ip():
            """API: разблокировка IP"""
            try:
                data = request.get_json()
                if not data or 'ip' not in data:
                    return jsonify({'success': False, 'error': 'IP address required'}), 400
                
                ip_addr = data['ip']
                success = self.blocker.unblock_ip(ip_addr, 'manual_web')
                
                return jsonify({
                    'success': success,
                    'message': f"IP {ip_addr} {'разблокирован' if success else 'не найден'}"
                })
            except Exception as e:
                logging.error("Ошибка разблокировки IP: %s", e)
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/stats')
        def get_stats():
            """API: получение общей статистики"""
            try:
                # Статистика логов
                log_stats = self.event_logger.get_stats()
                
                # Статистика блокировок
                block_stats = self.blocker.get_block_stats()
                
                # Последние события для анализа
                recent_events = self.event_logger.get_recent_events(200)
                
                # Группировка по правилам
                rules_stats = Counter(event.get('rule_name', 'unknown') for event in recent_events)
                
                # Статистика по времени (последние 24 часа по часам)
                hourly_stats = defaultdict(int)
                current_time = datetime.now()
                
                for event in recent_events:
                    event_time = datetime.fromtimestamp(event.get('timestamp', 0))
                    if (current_time - event_time).days == 0:  # Сегодня
                        hour_key = event_time.strftime('%H:00')
                        hourly_stats[hour_key] += 1
                
                # Top атакующие IP
                top_attackers = Counter(event.get('src_ip', 'unknown') for event in recent_events).most_common(10)
                
                # Статистика по типам атак за последние 7 дней
                weekly_attacks = defaultdict(lambda: defaultdict(int))
                for event in recent_events:
                    event_time = datetime.fromtimestamp(event.get('timestamp', 0))
                    days_ago = (current_time - event_time).days
                    if days_ago < 7:
                        day_key = event_time.strftime('%Y-%m-%d')
                        rule = event.get('rule_name', 'unknown')
                        weekly_attacks[day_key][rule] += 1
                
                return jsonify({
                    'success': True,
                    'stats': {
                        'logs': log_stats,
                        'blocking': block_stats,
                        'rules': dict(rules_stats),
                        'recent_events_count': len(recent_events),
                        'hourly_stats': dict(hourly_stats),
                        'top_attackers': top_attackers,
                        'weekly_attacks': dict(weekly_attacks)
                    }
                })
            except Exception as e:
                logging.error("Ошибка получения статистики: %s", e)
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/rules')
        def get_rules():
            """API: получение списка доступных правил"""
            try:
                recent_events = self.event_logger.get_recent_events(100)
                rules = list(set(event.get('rule_name', '') for event in recent_events))
                rules = [r for r in rules if r]  # Убираем пустые
                rules.sort()
                
                return jsonify({
                    'success': True,
                    'rules': rules
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/charts/attacks_by_hour')
        def chart_attacks_by_hour():
            """API: данные для графика атак по часам"""
            try:
                events = self.event_logger.get_recent_events(500)
                
                # Группировка по часам за последние 24 часа
                hourly_data = defaultdict(int)
                current_time = datetime.now()
                
                # Инициализация всех часов
                for i in range(24):
                    hour_time = current_time - timedelta(hours=i)
                    hour_key = hour_time.strftime('%H:00')
                    hourly_data[hour_key] = 0
                
                # Подсчет событий
                for event in events:
                    event_time = datetime.fromtimestamp(event.get('timestamp', 0))
                    if (current_time - event_time).total_seconds() <= 24 * 3600:
                        hour_key = event_time.strftime('%H:00')
                        hourly_data[hour_key] += 1
                
                # Сортировка по времени
                sorted_hours = sorted(hourly_data.keys())
                chart_data = {
                    'labels': sorted_hours,
                    'data': [hourly_data[hour] for hour in sorted_hours]
                }
                
                return jsonify({
                    'success': True,
                    'chart_data': chart_data
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/charts/attacks_by_type')
        def chart_attacks_by_type():
            """API: данные для графика атак по типам"""
            try:
                events = self.event_logger.get_recent_events(200)
                
                # Подсчет по типам атак
                attack_types = Counter(event.get('rule_name', 'unknown') for event in events)
                
                chart_data = {
                    'labels': list(attack_types.keys()),
                    'data': list(attack_types.values())
                }
                
                return jsonify({
                    'success': True,
                    'chart_data': chart_data
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/clear_logs', methods=['POST'])
        def clear_logs():
            """API: очистка логов"""
            try:
                data = request.get_json() or {}
                log_type = data.get('type', 'events')
                
                if log_type == 'events':
                    events_file = self.config.get('LOGGING', 'events_file', 
                                                fallback='/var/log/mprs/events.json')
                    if os.path.exists(events_file):
                        # Создаем backup перед очисткой
                        backup_file = f"{events_file}.backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                        os.rename(events_file, backup_file)
                        
                        message = f"События очищены, backup: {os.path.basename(backup_file)}"
                    else:
                        message = "Файл событий не существует"
                        
                elif log_type == 'blocks':
                    blocks_file = self.config.get('LOGGING', 'blocked_ips_file',
                                                fallback='/var/log/mprs/blocked_ips.json')
                    if os.path.exists(blocks_file):
                        backup_file = f"{blocks_file}.backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                        os.rename(blocks_file, backup_file)
                        
                        message = f"История блокировок очищена, backup: {os.path.basename(backup_file)}"
                    else:
                        message = "Файл блокировок не существует"
                        
                else:
                    return jsonify({'success': False, 'error': 'Unknown log type'}), 400
                
                return jsonify({
                    'success': True,
                    'message': message
                })
            except Exception as e:
                logging.error("Ошибка очистки логов: %s", e)
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/block_ip', methods=['POST'])
        def manual_block_ip():
            """API: ручная блокировка IP"""
            try:
                data = request.get_json()
                if not data or 'ip' not in data:
                    return jsonify({'success': False, 'error': 'IP address required'}), 400
                
                ip_addr = data['ip']
                block_type = data.get('type', 'soft_block')
                reason = data.get('reason', 'manual_web_block')
                
                success = self.blocker.block_ip(ip_addr, block_type, reason)
                
                return jsonify({
                    'success': success,
                    'message': f"IP {ip_addr} {'заблокирован' if success else 'не удалось заблокировать'}"
                })
            except Exception as e:
                logging.error("Ошибка блокировки IP: %s", e)
                return jsonify({'success': False, 'error': str(e)}), 500
    
    def run(self):
        """Запуск веб-сервера"""
        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=self.debug,
                threaded=True,
                use_reloader=False
            )
        except Exception as e:
            logging.error("Ошибка запуска веб-сервера: %s", e)

# HTML шаблон с улучшенным интерфейсом
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MPRS - Панель управления</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f5f5; 
            color: #333; 
            line-height: 1.6;
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 1rem; 
            text-align: center; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .nav-tabs {
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 0;
            display: flex;
            justify-content: center;
        }
        .nav-tab {
            padding: 1rem 2rem;
            background: transparent;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 1rem;
            color: #666;
        }
        .nav-tab.active {
            background: #667eea;
            color: white;
        }
        .nav-tab:hover {
            background: #5a67d8;
            color: white;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 2rem; 
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .dashboard { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 2rem; 
            margin-bottom: 2rem; 
        }
        .card { 
            background: white; 
            border-radius: 8px; 
            padding: 1.5rem; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
            transition: transform 0.2s;
        }
        .card:hover { transform: translateY(-2px); }
        .card h3 { 
            color: #667eea; 
            margin-bottom: 1rem; 
            border-bottom: 2px solid #eee; 
            padding-bottom: 0.5rem;
        }
        .chart-container {
            position: relative;
            height: 400px;
            margin: 1rem 0;
        }
        .controls {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .controls-row {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }
        .form-group {
            display: flex;
            flex-direction: column;
            min-width: 120px;
        }
        .form-group label {
            font-size: 0.9rem;
            color: #666;
            margin-bottom: 0.25rem;
        }
        input[type="text"], select {
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
        }
        .stat { 
            display: flex; 
            justify-content: space-between; 
            margin: 0.5rem 0; 
            padding: 0.5rem 0;
        }
        .stat-value { 
            font-weight: bold; 
            color: #667eea; 
        }
        .table-container { 
            overflow-x: auto; 
            margin-top: 1rem;
            max-height: 600px;
            overflow-y: auto;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        th, td { 
            padding: 0.75rem; 
            text-align: left; 
            border-bottom: 1px solid #eee; 
        }
        th { 
            background: #667eea; 
            color: white; 
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        tr:hover { background: #f8f9ff; }
        .btn { 
            background: #667eea; 
            color: white; 
            border: none; 
            padding: 0.5rem 1rem; 
            border-radius: 4px; 
            cursor: pointer; 
            transition: background 0.2s;
            margin: 0.25rem;
        }
        .btn:hover { background: #5a67d8; }
        .btn-danger { background: #e53e3e; }
        .btn-danger:hover { background: #c53030; }
        .btn-success { background: #48bb78; }
        .btn-success:hover { background: #38a169; }
        .btn-warning { background: #ed8936; }
        .btn-warning:hover { background: #dd6b20; }
        .status { padding: 0.25rem 0.5rem; border-radius: 4px; color: white; font-size: 0.875rem; }
        .status-soft { background: #f6ad55; }
        .status-hard { background: #e53e3e; }
        .loading { text-align: center; color: #667eea; }
        .error { color: #e53e3e; background: #fed7d7; padding: 1rem; border-radius: 4px; margin: 1rem 0; }
        .success { color: #38a169; background: #c6f6d5; padding: 1rem; border-radius: 4px; margin: 1rem 0; }
        .pagination {
            display: flex;
            justify-content: center;
            gap: 0.5rem;
            margin-top: 1rem;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        .modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 2rem;
            border-radius: 8px;
            width: 90%;
            max-width: 500px;
        }
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        .close:hover { color: black; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ MPRS - Minimal Prevention & Response System</h1>
        <p>Расширенная панель управления системой обнаружения и предотвращения вторжений</p>
    </div>
    
    <nav class="nav-tabs">
        <button class="nav-tab active" onclick="showTab('dashboard')">📊 Дашборд</button>
        <button class="nav-tab" onclick="showTab('events')">🔥 События</button>
        <button class="nav-tab" onclick="showTab('blocked')">🚫 Блокировки</button>
        <button class="nav-tab" onclick="showTab('analytics')">📈 Аналитика</button>
        <button class="nav-tab" onclick="showTab('management')">⚙️ Управление</button>
    </nav>
    
    <div class="container">
        <!-- Dashboard Tab -->
        <div id="dashboard" class="tab-content active">
            <div class="controls">
                <button class="btn btn-success" onclick="refreshAll()">🔄 Обновить все</button>
                <button class="btn btn-warning" onclick="toggleAutoRefresh()" id="autoRefreshBtn">⏸️ Авто-обновление</button>
            </div>
            
            <div class="dashboard">
                <div class="card">
                    <h3>📊 Статистика системы</h3>
                    <div id="stats-content" class="loading">Загрузка...</div>
                </div>
                
                <div class="card">
                    <h3>🚫 Активные блокировки</h3>
                    <div id="blocked-stats" class="loading">Загрузка...</div>
                </div>
                
                <div class="card">
                    <h3>🎯 Топ атакующие</h3>
                    <div id="top-attackers" class="loading">Загрузка...</div>
                </div>
            </div>
        </div>

        <!-- Events Tab -->
        <div id="events" class="tab-content">
            <div class="controls">
                <div class="controls-row">
                    <div class="form-group">
                        <label>Поиск по IP:</label>
                        <input type="text" id="search-ip" placeholder="192.168.1.1">
                    </div>
                    <div class="form-group">
                        <label>Правило:</label>
                        <select id="rule-filter">
                            <option value="">Все правила</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Сортировка:</label>
                        <select id="sort-by">
                            <option value="timestamp">По времени</option>
                            <option value="rule_name">По правилу</option>
                            <option value="src_ip">По IP</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Порядок:</label>
                        <select id="sort-order">
                            <option value="desc">Убывание</option>
                            <option value="asc">Возрастание</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Количество:</label>
                        <select id="events-limit">
                            <option value="50">50</option>
                            <option value="100">100</option>
                            <option value="200">200</option>
                            <option value="500">500</option>
                        </select>
                    </div>
                    <button class="btn" onclick="loadEvents()">🔍 Поиск</button>
                </div>
            </div>
            
            <div class="card">
                <h3>🔥 События безопасности</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Время</th>
                                <th>Правило</th>
                                <th>IP атакующего</th>
                                <th>Цель</th>
                                <th>Описание</th>
                                <th>Действие</th>
                                <th>Управление</th>
                            </tr>
                        </thead>
                        <tbody id="events-table">
                            <tr><td colspan="7" class="loading">Загрузка событий...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Blocked IPs Tab -->
        <div id="blocked" class="tab-content">
            <div class="controls">
                <div class="controls-row">
                    <div class="form-group">
                        <label>Поиск IP:</label>
                        <input type="text" id="search-blocked-ip" placeholder="192.168.1.1">
                    </div>
                    <div class="form-group">
                        <label>Тип блокировки:</label>
                        <select id="block-type-filter">
                            <option value="">Все типы</option>
                            <option value="soft_block">Мягкие</option>
                            <option value="hard_block">Жесткие</option>
                        </select>
                    </div>
                    <button class="btn" onclick="loadBlocked()">🔍 Поиск</button>
                    <button class="btn btn-warning" onclick="showManualBlockModal()">➕ Заблокировать IP</button>
                </div>
            </div>
            
            <div class="card">
                <h3>🚫 Управление блокировками</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>IP адрес</th>
                                <th>Тип блокировки</th>
                                <th>Причина</th>
                                <th>Заблокирован</th>
                                <th>Осталось</th>
                                <th>Действие</th>
                            </tr>
                        </thead>
                        <tbody id="blocked-table">
                            <tr><td colspan="6" class="loading">Загрузка...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Analytics Tab -->
        <div id="analytics" class="tab-content">
            <div class="dashboard">
                <div class="card">
                    <h3>📈 Атаки по часам (24ч)</h3>
                    <div class="chart-container">
                        <canvas id="hourlyChart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <h3>🎯 Распределение по типам атак</h3>
                    <div class="chart-container">
                        nvas is id="attackTypesChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Management Tab -->
        <div id="management" class="tab-content">
            <div class="dashboard">
                <div class="card">
                    <h3>🧹 Очистка данных</h3>
                    <p>Очистка логов создает backup файлы перед удалением.</p>
                    <button class="btn btn-warning" onclick="clearLogs('events')">🗑️ Очистить события</button>
                    <button class="btn btn-warning" onclick="clearLogs('blocks')">🗑️ Очистить историю блокировок</button>
                    <div id="clear-status"></div>
                </div>
                
                <div class="card">
                    <h3>⚙️ Системная информация</h3>
                    <div id="system-info" class="loading">Загрузка...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Manual Block Modal -->
    <div id="manualBlockModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('manualBlockModal')">&times;</span>
            <h3>Ручная блокировка IP</h3>
            <div class="form-group">
                <label>IP адрес:</label>
                <input type="text" id="manual-block-ip" placeholder="192.168.1.1">
            </div>
            <div class="form-group">
                <label>Тип блокировки:</label>
                <select id="manual-block-type">
                    <option value="soft_block">Мягкая блокировка (5 мин)</option>
                    <option value="hard_block">Жесткая блокировка (1 час)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Причина:</label>
                <input type="text" id="manual-block-reason" placeholder="Manual block via web interface">
            </div>
            <button class="btn btn-danger" onclick="executeManualBlock()">🚫 Заблокировать</button>
        </div>
    </div>

    <script>
        let autoRefresh = true;
        let hourlyChart, attackTypesChart;
        
        // Tab management
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
            
            // Load data for specific tabs
            if (tabName === 'analytics') {
                loadCharts();
            } else if (tabName === 'events') {
                loadRules();
                loadEvents();
            } else if (tabName === 'blocked') {
                loadBlocked();
            } else if (tabName === 'management') {
                loadSystemInfo();
            }
        }
        
        // API helper
        async function apiCall(url, options = {}) {
            try {
                const response = await fetch(url, options);
                const data = await response.json();
                if (!data.success) {
                    throw new Error(data.error || 'API Error');
                }
                return data;
            } catch (error) {
                console.error('API Call failed:', error);
                throw error;
            }
        }
        
        // Load statistics
        async function loadStats() {
            try {
                const data = await apiCall('/api/stats');
                const stats = data.stats;
                
                document.getElementById('stats-content').innerHTML = `
                    <div class="stat"><span>Всего событий:</span><span class="stat-value">${stats.logs.total_events || 0}</span></div>
                    <div class="stat"><span>За последние часы:</span><span class="stat-value">${stats.recent_events_count || 0}</span></div>
                    <div class="stat"><span>Размер лог-файла:</span><span class="stat-value">${formatBytes(stats.logs.events_file_size || 0)}</span></div>
                `;
                
                document.getElementById('blocked-stats').innerHTML = `
                    <div class="stat"><span>Всего заблокировано:</span><span class="stat-value">${stats.blocking.total_blocked || 0}</span></div>
                    <div class="stat"><span>Мягкие блокировки:</span><span class="stat-value">${stats.blocking.soft_blocks || 0}</span></div>
                    <div class="stat"><span>Жесткие блокировки:</span><span class="stat-value">${stats.blocking.hard_blocks || 0}</span></div>
                `;
                
                // Top attackers
                const topAttackers = stats.top_attackers || [];
                const attackersHtml = topAttackers.length > 0 
                    ? topAttackers.map(([ip, count]) => `
                        <div class="stat">
                            <span><code>${ip}</code></span>
                            <span class="stat-value">${count} атак</span>
                        </div>
                    `).join('')
                    : '<div class="stat"><span>Нет данных</span></div>';
                
                document.getElementById('top-attackers').innerHTML = attackersHtml;
                
            } catch (error) {
                document.getElementById('stats-content').innerHTML = `<div class="error">Ошибка загрузки статистики: ${error.message}</div>`;
            }
        }
        
        // Load events with filters
        async function loadEvents() {
            try {
                const searchIp = document.getElementById('search-ip').value;
                const ruleFilter = document.getElementById('rule-filter').value;
                const sortBy = document.getElementById('sort-by').value;
                const sortOrder = document.getElementById('sort-order').value;
                const limit = document.getElementById('events-limit').value;
                
                const params = new URLSearchParams({
                    limit: limit,
                    sort: sortBy,
                    order: sortOrder
                });
                
                if (searchIp) params.append('search_ip', searchIp);
                if (ruleFilter) params.append('rule', ruleFilter);
                
                const data = await apiCall(`/api/events?${params}`);
                const tbody = document.getElementById('events-table');
                
                if (data.events.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="loading">Нет событий</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.events.map(event => `
                    <tr>
                        <td>${formatTime(event.timestamp)}</td>
                        <td><strong>${event.rule_name}</strong></td>
                        <td><code>${event.src_ip}</code></td>
                        <td>${event.dst_ip}${event.dst_port ? ':' + event.dst_port : ''}</td>
                        <td>${event.description}</td>
                        <td><span class="status status-${event.action.includes('hard') ? 'hard' : 'soft'}">${event.action}</span></td>
                        <td>
                            <button class="btn btn-danger" onclick="blockIP('${event.src_ip}', 'hard_block')" title="Hard Block">
                                🔒
                            </button>
                        </td>
                    </tr>
                `).join('');
            } catch (error) {
                document.getElementById('events-table').innerHTML = `<tr><td colspan="7" class="error">Ошибка: ${error.message}</td></tr>`;
            }
        }
        
        // Load blocked IPs with filters
        async function loadBlocked() {
            try {
                const searchIp = document.getElementById('search-blocked-ip').value;
                const blockType = document.getElementById('block-type-filter').value;
                
                const params = new URLSearchParams();
                if (searchIp) params.append('search_ip', searchIp);
                if (blockType) params.append('type', blockType);
                
                const data = await apiCall(`/api/blocked?${params}`);
                const tbody = document.getElementById('blocked-table');
                
                if (data.blocked_ips.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="loading">Нет заблокированных IP</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.blocked_ips.map(block => `
                    <tr>
                        <td><code>${block.ip}</code></td>
                        <td><span class="status status-${block.type.includes('hard') ? 'hard' : 'soft'}">${block.type}</span></td>
                        <td>${block.reason}</td>
                        <td>${formatTime(block.blocked_at)}</td>
                        <td>${formatDuration(block.remaining)}</td>
                        <td>
                            <button class="btn btn-danger" onclick="unblockIP('${block.ip}')">
                                🚫 Разблокировать
                            </button>
                        </td>
                    </tr>
                `).join('');
            } catch (error) {
                document.getElementById('blocked-table').innerHTML = `<tr><td colspan="6" class="error">Ошибка: ${error.message}</td></tr>`;
            }
        }
        
        // Load rules for filter
        async function loadRules() {
            try {
                const data = await apiCall('/api/rules');
                const select = document.getElementById('rule-filter');
                
                // Clear existing options (except first)
                select.innerHTML = '<option value="">Все правила</option>';
                
                data.rules.forEach(rule => {
                    const option = document.createElement('option');
                    option.value = rule;
                    option.textContent = rule;
                    select.appendChild(option);
                });
            } catch (error) {
                console.error('Ошибка загрузки правил:', error);
            }
        }
        
        // Load charts
        async function loadCharts() {
            try {
                // Hourly attacks chart
                const hourlyData = await apiCall('/api/charts/attacks_by_hour');
                
                if (hourlyChart) {
                    hourlyChart.destroy();
                }
                
                const ctx1 = document.getElementById('hourlyChart').getContext('2d');
                hourlyChart = new Chart(ctx1, {
                    type: 'line',
                    data: {
                        labels: hourlyData.chart_data.labels,
                        datasets: [{
                            label: 'Атаки',
                            data: hourlyData.chart_data.data,
                            borderColor: '#667eea',
                            backgroundColor: 'rgba(102, 126, 234, 0.1)',
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
                
                // Attack types chart
                const typeData = await apiCall('/api/charts/attacks_by_type');
                
                if (attackTypesChart) {
                    attackTypesChart.destroy();
                }
                
                const ctx2 = document.getElementById('attackTypesChart').getContext('2d');
                attackTypesChart = new Chart(ctx2, {
                    type: 'doughnut',
                    data: {
                        labels: typeData.chart_data.labels,
                        datasets: [{
                            data: typeData.chart_data.data,
                            backgroundColor: [
                                '#667eea', '#764ba2', '#f093fb', '#f5576c',
                                '#4ecdc4', '#45b7d1', '#96ceb4', '#ffecd2'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false
                    }
                });
                
            } catch (error) {
                console.error('Ошибка загрузки графиков:', error);
            }
        }
        
        // System management functions
        async function clearLogs(type) {
            if (!confirm(`Очистить ${type === 'events' ? 'события' : 'историю блокировок'}? Будет создан backup.`)) {
                return;
            }
            
            try {
                const data = await apiCall('/api/clear_logs', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({type: type})
                });
                
                document.getElementById('clear-status').innerHTML = 
                    `<div class="success">${data.message}</div>`;
                
                // Refresh data
                if (type === 'events') {
                    loadEvents();
                }
                loadStats();
                
            } catch (error) {
                document.getElementById('clear-status').innerHTML = 
                    `<div class="error">Ошибка: ${error.message}</div>`;
            }
        }
        
        async function loadSystemInfo() {
            try {
                const data = await apiCall('/api/stats');
                const stats = data.stats;
                
                document.getElementById('system-info').innerHTML = `
                    <div class="stat"><span>Размер логов событий:</span><span class="stat-value">${formatBytes(stats.logs.events_file_size || 0)}</span></div>
                    <div class="stat"><span>Размер логов блокировок:</span><span class="stat-value">${formatBytes(stats.logs.blocks_file_size || 0)}</span></div>
                    <div class="stat"><span>Всего событий:</span><span class="stat-value">${stats.logs.total_events || 0}</span></div>
                    <div class="stat"><span>Всего блокировок:</span><span class="stat-value">${stats.logs.total_blocks || 0}</span></div>
                `;
            } catch (error) {
                document.getElementById('system-info').innerHTML = 
                    `<div class="error">Ошибка загрузки: ${error.message}</div>`;
            }
        }
        
        // Manual block functions
        function showManualBlockModal() {
            document.getElementById('manualBlockModal').style.display = 'block';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        async function executeManualBlock() {
            const ip = document.getElementById('manual-block-ip').value;
            const type = document.getElementById('manual-block-type').value;
            const reason = document.getElementById('manual-block-reason').value || 'Manual block via web interface';
            
            if (!ip) {
                alert('Введите IP адрес');
                return;
            }
            
            try {
                const data = await apiCall('/api/block_ip', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip, type: type, reason: reason})
                });
                
                alert(data.message);
                closeModal('manualBlockModal');
                loadBlocked();
                loadStats();
                
            } catch (error) {
                alert(`Ошибка блокировки: ${error.message}`);
            }
        }
        
        // Quick actions
        async function blockIP(ip, type) {
            if (!confirm(`Заблокировать IP ${ip}?`)) return;
            
            try {
                const data = await apiCall('/api/block_ip', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip, type: type, reason: 'manual_from_events'})
                });
                
                alert(data.message);
                loadBlocked();
                loadStats();
            } catch (error) {
                alert(`Ошибка блокировки: ${error.message}`);
            }
        }
        
        async function unblockIP(ip) {
            if (!confirm(`Разблокировать IP ${ip}?`)) return;
            
            try {
                const data = await apiCall('/api/unblock', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip})
                });
                
                alert(data.message);
                loadBlocked();
                loadStats();
            } catch (error) {
                alert(`Ошибка разблокировки: ${error.message}`);
            }
        }
        
        // Utility functions
        function toggleAutoRefresh() {
            autoRefresh = !autoRefresh;
            const btn = document.getElementById('autoRefreshBtn');
            btn.innerHTML = autoRefresh ? '⏸️ Авто-обновление' : '▶️ Авто-обновление';
            btn.className = autoRefresh ? 'btn btn-warning' : 'btn';
        }
        
        function refreshAll() {
            loadStats();
            const activeTab = document.querySelector('.tab-content.active').id;
            if (activeTab === 'events') {
                loadEvents();
            } else if (activeTab === 'blocked') {
                loadBlocked();
            } else if (activeTab === 'analytics') {
                loadCharts();
            }
        }
        
        function formatTime(timestamp) {
            return new Date(timestamp * 1000).toLocaleString('ru-RU');
        }
        
        function formatDuration(seconds) {
            if (seconds <= 0) return 'Истек';
            
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;
            
            if (hours > 0) return `${hours}ч ${minutes}м`;
            if (minutes > 0) return `${minutes}м ${secs}с`;
            return `${secs}с`;
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Auto-refresh
        setInterval(() => {
            if (autoRefresh) {
                loadStats();
                const activeTab = document.querySelector('.tab-content.active').id;
                if (activeTab === 'blocked') {
                    loadBlocked();
                }
            }
        }, 30000);
        
        // Initial load
        document.addEventListener('DOMContentLoaded', function() {
            loadStats();
            loadRules();
        });
        
        // Close modal on outside click
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
'''
