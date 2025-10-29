#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPRS Web UI Module
Простой веб-интерфейс для управления и мониторинга MPRS
"""

import logging
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_from_directory

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
            """API: получение событий"""
            try:
                limit = request.args.get('limit', 100, type=int)
                event_type = request.args.get('type', None)
                
                events = self.event_logger.get_recent_events(limit, event_type)
                return jsonify({
                    'success': True,
                    'events': events,
                    'count': len(events)
                })
            except Exception as e:
                logging.error("Ошибка получения событий: %s", e)
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/blocked')
        def get_blocked():
            """API: получение заблокированных IP"""
            try:
                blocked_ips = self.blocker.get_blocked_ips()
                block_stats = self.blocker.get_block_stats()
                
                # Преобразуем данные для JSON
                blocked_list = []
                for ip, info in blocked_ips.items():
                    blocked_list.append({
                        'ip': ip,
                        'type': info['type'],
                        'reason': info['reason'],
                        'blocked_at': info['blocked_at'],
                        'until': info['until'],
                        'remaining': max(0, int(info['until'] - datetime.now().timestamp()))
                    })
                
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
                
                # Последние события по типам
                recent_events = self.event_logger.get_recent_events(50)
                
                # Группировка по правилам
                rules_stats = {}
                for event in recent_events:
                    rule_name = event.get('rule_name', 'unknown')
                    if rule_name not in rules_stats:
                        rules_stats[rule_name] = 0
                    rules_stats[rule_name] += 1
                
                return jsonify({
                    'success': True,
                    'stats': {
                        'logs': log_stats,
                        'blocking': block_stats,
                        'rules': rules_stats,
                        'recent_events_count': len(recent_events)
                    }
                })
            except Exception as e:
                logging.error("Ошибка получения статистики: %s", e)
                return jsonify({'success': False, 'error': str(e)}), 500
    
    def run(self):
        """Запуск веб-сервера"""
        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=self.debug,
                threaded=True,
                use_reloader=False  # Отключаем reloader для daemon режима
            )
        except Exception as e:
            logging.error("Ошибка запуска веб-сервера: %s", e)

# HTML шаблон для веб-интерфейса
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MPRS - Панель управления</title>
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
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 2rem; 
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
        }
        .btn:hover { background: #5a67d8; }
        .btn-danger { background: #e53e3e; }
        .btn-danger:hover { background: #c53030; }
        .status { padding: 0.25rem 0.5rem; border-radius: 4px; color: white; font-size: 0.875rem; }
        .status-soft { background: #f6ad55; }
        .status-hard { background: #e53e3e; }
        .loading { text-align: center; color: #667eea; }
        .error { color: #e53e3e; background: #fed7d7; padding: 1rem; border-radius: 4px; margin: 1rem 0; }
        .refresh-btn { 
            float: right; 
            background: #48bb78; 
            margin-bottom: 1rem;
        }
        .refresh-btn:hover { background: #38a169; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ MPRS - Minimal Prevention & Response System</h1>
        <p>Панель управления системой обнаружения и предотвращения вторжений</p>
    </div>
    
    <div class="container">
        <button class="btn refresh-btn" onclick="refreshAll()">🔄 Обновить все</button>
        
        <div class="dashboard">
            <div class="card">
                <h3>📊 Статистика системы</h3>
                <div id="stats-content" class="loading">Загрузка...</div>
            </div>
            
            <div class="card">
                <h3>🚫 Заблокированные IP</h3>
                <div id="blocked-stats" class="loading">Загрузка...</div>
            </div>
        </div>
        
        <div class="card">
            <h3>🔥 Последние события</h3>
            <button class="btn" onclick="loadEvents()">🔄 Обновить события</button>
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
                        </tr>
                    </thead>
                    <tbody id="events-table">
                        <tr><td colspan="6" class="loading">Загрузка событий...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="card">
            <h3>🚫 Управление блокировками</h3>
            <button class="btn" onclick="loadBlocked()">🔄 Обновить список</button>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>IP адрес</th>
                            <th>Тип блокировки</th>
                            <th>Причина</th>
                            <th>Осталось</th>
                            <th>Действие</th>
                        </tr>
                    </thead>
                    <tbody id="blocked-table">
                        <tr><td colspan="5" class="loading">Загрузка...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let autoRefresh = true;
        
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
        
        async function loadStats() {
            try {
                const data = await apiCall('/api/stats');
                const stats = data.stats;
                
                document.getElementById('stats-content').innerHTML = `
                    <div class="stat"><span>Всего событий:</span><span class="stat-value">${stats.logs.total_events || 0}</span></div>
                    <div class="stat"><span>Недавних событий:</span><span class="stat-value">${stats.recent_events_count || 0}</span></div>
                    <div class="stat"><span>Размер лог-файла:</span><span class="stat-value">${formatBytes(stats.logs.events_file_size || 0)}</span></div>
                `;
                
                document.getElementById('blocked-stats').innerHTML = `
                    <div class="stat"><span>Всего заблокировано:</span><span class="stat-value">${stats.blocking.total_blocked || 0}</span></div>
                    <div class="stat"><span>Мягкие блокировки:</span><span class="stat-value">${stats.blocking.soft_blocks || 0}</span></div>
                    <div class="stat"><span>Жесткие блокировки:</span><span class="stat-value">${stats.blocking.hard_blocks || 0}</span></div>
                `;
            } catch (error) {
                document.getElementById('stats-content').innerHTML = `<div class="error">Ошибка загрузки статистики: ${error.message}</div>`;
            }
        }
        
        async function loadEvents() {
            try {
                const data = await apiCall('/api/events?limit=20');
                const tbody = document.getElementById('events-table');
                
                if (data.events.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="loading">Нет событий</td></tr>';
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
                    </tr>
                `).join('');
            } catch (error) {
                document.getElementById('events-table').innerHTML = `<tr><td colspan="6" class="error">Ошибка: ${error.message}</td></tr>`;
            }
        }
        
        async function loadBlocked() {
            try {
                const data = await apiCall('/api/blocked');
                const tbody = document.getElementById('blocked-table');
                
                if (data.blocked_ips.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="loading">Нет заблокированных IP</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.blocked_ips.map(block => `
                    <tr>
                        <td><code>${block.ip}</code></td>
                        <td><span class="status status-${block.type.includes('hard') ? 'hard' : 'soft'}">${block.type}</span></td>
                        <td>${block.reason}</td>
                        <td>${formatDuration(block.remaining)}</td>
                        <td>
                            <button class="btn btn-danger" onclick="unblockIP('${block.ip}')">
                                🚫 Разблокировать
                            </button>
                        </td>
                    </tr>
                `).join('');
            } catch (error) {
                document.getElementById('blocked-table').innerHTML = `<tr><td colspan="5" class="error">Ошибка: ${error.message}</td></tr>`;
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
                loadBlocked(); // Перезагружаем список
                loadStats(); // Обновляем статистику
            } catch (error) {
                alert(`Ошибка разблокировки: ${error.message}`);
            }
        }
        
        function refreshAll() {
            loadStats();
            loadEvents();
            loadBlocked();
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
        
        // Автообновление каждые 30 секунд
        setInterval(() => {
            if (autoRefresh) {
                loadStats();
                loadBlocked();
            }
        }, 30000);
        
        // Начальная загрузка
        refreshAll();
    </script>
</body>
</html>
'''
