#!/bin/bash

set -e

echo "=== MPRS Installation/Update Script ==="

# Проверка root прав
if [[ $EUID -ne 0 ]]; then
   echo "Этот скрипт должен запускаться с правами root (sudo)" 
   exit 1
fi

# Определяем режим работы
if [[ -f "/etc/mprs/mprs.conf" ]] && [[ -f "/opt/mprs/venv/bin/python3" ]]; then
    MODE="UPDATE"
    echo "🔄 Обнаружена существующая установка - режим ОБНОВЛЕНИЯ"
else
    MODE="INSTALL"
    echo "🆕 Новая установка MPRS"
fi

# Остановка сервиса если работает
if systemctl is-active --quiet mprs 2>/dev/null; then
    echo "⏹️ Остановка MPRS сервиса..."
    systemctl stop mprs
    RESTART_SERVICE=true
else
    RESTART_SERVICE=false
fi

# Проверка дистрибутива (только для новой установки)
if [[ "$MODE" == "INSTALL" ]]; then
    if command -v apt &> /dev/null; then
        PKG_MANAGER="apt"
        PKG_UPDATE="apt update"
        PKG_INSTALL="apt install -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        PKG_UPDATE="yum update -y"
        PKG_INSTALL="yum install -y"
    else
        echo "❌ Неподдерживаемый дистрибутив. Требуется apt или yum."
        exit 1
    fi
    
    # Установка системных пакетов
    echo "📦 Установка системных зависимостей..."
    $PKG_UPDATE
    
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        $PKG_INSTALL python3 python3-venv python3-pip iptables libpcap-dev libcap2-bin
    else
        $PKG_INSTALL python3 python3-pip iptables libpcap-devel libcap
    fi
fi

# Создание пользователя mprs (только для новой установки)
if [[ "$MODE" == "INSTALL" ]] && ! id "mprs" &>/dev/null; then
    echo "👤 Создание пользователя mprs..."
    useradd -r -s /bin/false -d /opt/mprs mprs
fi

# Создание каталогов
echo "📁 Создание/проверка каталогов..."
mkdir -p /opt/mprs/{src,config,logs}
mkdir -p /var/log/mprs
mkdir -p /etc/mprs

# ===== ОБНОВЛЕНИЕ КОДА =====
echo "📝 Обновление кода..."

# Создание backup старых файлов при обновлении
if [[ "$MODE" == "UPDATE" ]]; then
    BACKUP_DIR="/opt/mprs/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    echo "💾 Создание backup в $BACKUP_DIR"
    
    # Backup Python файлов
    if [[ -d "/opt/mprs/src" ]]; then
        cp -r /opt/mprs/src/* "$BACKUP_DIR/" 2>/dev/null || true
    fi
fi

# Обновление Python файлов
PYTHON_FILES=(main.py sniffer.py analyzer.py blocker.py notifier.py logger.py web_ui.py utils.py)
UPDATED_FILES=0

for file in "${PYTHON_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        cp "$file" /opt/mprs/src/
        echo "  ✅ $file"
        ((UPDATED_FILES++))
    else
        echo "  ⚠️  $file - не найден"
    fi
done

echo "📊 Обновлено файлов кода: $UPDATED_FILES"

# ===== СОХРАНЕНИЕ КОНФИГУРАЦИЙ =====
echo "⚙️  Обработка конфигураций..."

# Функция для безопасного обновления конфигурации
update_config_safe() {
    local file=$1
    local source_file=$2
    
    if [[ -f "/etc/mprs/$file" ]]; then
        echo "  📋 $file - существует, сохраняем"
        # Создаем backup
        cp "/etc/mprs/$file" "/etc/mprs/$file.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
        
        # Если есть новая версия в текущем каталоге - показываем diff
        if [[ -f "$source_file" ]]; then
            if ! diff -q "/etc/mprs/$file" "$source_file" &>/dev/null; then
                echo "  🔄 Обнаружены изменения в $file"
                echo "  💡 Новая версия сохранена как /etc/mprs/$file.new"
                cp "$source_file" "/etc/mprs/$file.new"
            fi
        fi
    else
        if [[ -f "$source_file" ]]; then
            echo "  🆕 Создание $file"
            cp "$source_file" "/etc/mprs/$file"
        else
            echo "  🔧 Создание $file по умолчанию"
            return 1  # Нужно создать по умолчанию
        fi
    fi
    return 0
}

# Обработка конфигурационных файлов
update_config_safe "mprs.conf" "mprs.conf" || create_default_config
update_config_safe "rules.yaml" "rules.yaml" || create_default_rules  
update_config_safe "whitelist.txt" "whitelist.txt" || create_default_whitelist

# Функции создания конфигураций по умолчанию
create_default_config() {
    # Автоопределение сетевого интерфейса
    DEFAULT_INTERFACE=$(ip route | grep '^default' | grep -o 'dev [^ ]*' | head -1 | awk '{print $2}')
    if [[ -z "$DEFAULT_INTERFACE" ]]; then
        DEFAULT_INTERFACE="eth0"
    fi
    
    cat > /etc/mprs/mprs.conf << EOF
[GENERAL]
interface = $DEFAULT_INTERFACE
log_level = INFO

[CAPTURE]
bpf_filter = tcp or udp or icmp
promisc_mode = true
snaplen = 1500

[BLOCKING]
soft_block_duration = 300
hard_block_duration = 3600
max_concurrent_blocks = 1000
whitelist_file = /etc/mprs/whitelist.txt

[TELEGRAM]
enabled = false
bot_token = 
chat_id = 
rate_limit = 10

[WEB]
enabled = true
host = 0.0.0.0
port = 8080
debug = false

[LOGGING]
events_file = /var/log/mprs/events.json
blocked_ips_file = /var/log/mprs/blocked_ips.json
rotate_size = 50MB
rotate_count = 5
EOF
}

create_default_whitelist() {
    # Получаем локальный IP автоматически
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    cat > /etc/mprs/whitelist.txt << EOF
# MPRS Whitelist - доверенные IP адреса
127.0.0.1
::1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Локальный IP сервера (автоопределение)
$LOCAL_IP
EOF
}

create_default_rules() {
    cat > /etc/mprs/rules.yaml << 'EOF'
ssh_bruteforce:
  type: rate
  proto: tcp
  dst_port: 22
  threshold: 10
  window: 60
  action: soft_block
  description: "SSH brute force attack detected"

http_bad_ua:
  type: signature
  proto: tcp
  dst_port: [80, 8080, 443]
  regex: "sqlmap|nikto|curl.*bot|python-requests|masscan|nmap|gobuster|wfuzz"
  action: soft_block
  description: "Suspicious HTTP User-Agent detected"

syn_flood:
  type: rate
  proto: tcp
  flags: "S"
  threshold: 50
  window: 10
  action: hard_block
  description: "SYN flood attack detected"

port_scan:
  type: rate
  proto: tcp
  flags: "S"
  unique_ports: true
  threshold: 20
  window: 30
  action: soft_block
  description: "Port scan detected"

icmp_flood:
  type: rate
  proto: icmp
  threshold: 30
  window: 10
  action: soft_block
  description: "ICMP flood detected"

web_shells:
  type: signature
  proto: tcp
  dst_port: [80, 443]
  uri_regex: "shell|webshell|cmd\\.php|c99\\.php|r57\\.php"
  action: hard_block
  description: "Web shell access attempt detected"
EOF
}

# Обновление requirements.txt
echo "📦 Обновление Python зависимостей..."
cat > /opt/mprs/requirements.txt << 'EOF'
scapy>=2.4.5
flask>=2.3.0
pyyaml>=6.0
requests>=2.28.0
psutil>=5.9.0
EOF

# ===== PYTHON ENVIRONMENT =====
cd /opt/mprs

if [[ ! -d "venv" ]] || [[ "$MODE" == "INSTALL" ]]; then
    echo "🐍 Создание виртуального окружения..."
    rm -rf venv  # Удаляем если есть поврежденное
    python3 -m venv venv
fi

echo "📚 Установка/обновление Python пакетов..."
source venv/bin/activate
pip install --upgrade pip >/dev/null 2>&1
pip install -r requirements.txt >/dev/null 2>&1
deactivate

# ===== ПРАВА ДОСТУПА =====
echo "🔐 Настройка прав доступа..."
chown -R mprs:mprs /opt/mprs
chown -R mprs:mprs /var/log/mprs  
chown -R mprs:mprs /etc/mprs

# Настройка прав для захвата пакетов (только при новой установке или изменении Python)
if [[ "$MODE" == "INSTALL" ]] || [[ ! -f "/opt/mprs/.capabilities_set" ]]; then
    echo "⚡ Настройка прав для захвата пакетов..."
    
    if command -v setcap &> /dev/null; then
        if setcap cap_net_raw,cap_net_admin+eip /opt/mprs/venv/bin/python3 2>/dev/null; then
            echo "✅ setcap успешно применен"
            CAPABILITY_METHOD="setcap"
            touch /opt/mprs/.capabilities_set
        else
            echo "⚠️ setcap неудачен, используем sudo wrapper"
            CAPABILITY_METHOD="sudo"
        fi
    else
        CAPABILITY_METHOD="sudo"
    fi
else
    # Проверяем существующий метод
    if [[ -f "/opt/mprs/.capabilities_set" ]]; then
        CAPABILITY_METHOD="setcap"
    else
        CAPABILITY_METHOD="sudo"
    fi
fi

# Создание sudo wrapper если нужно
if [[ "$CAPABILITY_METHOD" == "sudo" ]]; then
    cat > /opt/mprs/start_mprs.sh << 'EOF'
#!/bin/bash
cd /opt/mprs
exec /opt/mprs/venv/bin/python3 src/main.py
EOF
    chmod +x /opt/mprs/start_mprs.sh
    chown mprs:mprs /opt/mprs/start_mprs.sh
    
    if [[ ! -f "/etc/sudoers.d/mprs-packet-capture" ]]; then
        echo "mprs ALL=(ALL) NOPASSWD: /opt/mprs/start_mprs.sh" > /etc/sudoers.d/mprs-packet-capture
        chmod 440 /etc/sudoers.d/mprs-packet-capture
    fi
fi

# ===== SYSTEMD СЕРВИС =====
echo "🎯 Настройка systemd сервиса..."

# Создание __init__.py
touch /opt/mprs/src/__init__.py

# Генерация сервис файла в зависимости от метода capabilities
if [[ "$CAPABILITY_METHOD" == "setcap" ]]; then
    cat > /etc/systemd/system/mprs.service << 'EOF'
[Unit]
Description=MPRS - Minimal Prevention & Response System
After=network.target
Wants=network.target

[Service]
Type=simple
User=mprs
Group=mprs
WorkingDirectory=/opt/mprs
Environment=PATH=/opt/mprs/venv/bin
ExecStart=/opt/mprs/venv/bin/python3 src/main.py
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/mprs /etc/mprs /opt/mprs/logs
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
else
    cat > /etc/systemd/system/mprs.service << 'EOF'
[Unit]  
Description=MPRS - Minimal Prevention & Response System
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/mprs
ExecStart=/opt/mprs/start_mprs.sh
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload

# Финальная настройка прав для конфигов
chmod 755 /etc/mprs
chmod 644 /etc/mprs/*

# ===== ЗАВЕРШЕНИЕ =====
echo ""
echo "🎉 === Установка/обновление завершено ==="
echo ""

if [[ "$MODE" == "UPDATE" ]]; then
    echo "📊 Статистика обновления:"
    echo "   • Обновлено файлов кода: $UPDATED_FILES"
    echo "   • Backup создан: $BACKUP_DIR"
    echo "   • Конфигурации сохранены"
fi

echo "🔧 Метод захвата пакетов: $CAPABILITY_METHOD"
echo ""
echo "🚀 Команды управления:"
echo "   Запуск:      sudo systemctl start mprs"
echo "   Остановка:   sudo systemctl stop mprs"  
echo "   Автозапуск:  sudo systemctl enable mprs"
echo "   Статус:      sudo systemctl status mprs"
echo ""
echo "📱 Веб-интерфейс: http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "📋 Мониторинг:"
echo "   Логи системы: sudo journalctl -u mprs -f"
echo "   Логи событий: sudo tail -f /var/log/mprs/events.json"
echo ""

# Автоматический запуск если сервис был остановлен нами
if [[ "$RESTART_SERVICE" == "true" ]]; then
    echo "🔄 Перезапуск сервиса..."
    systemctl start mprs
    sleep 2
    
    if systemctl is-active --quiet mprs; then
        echo "✅ MPRS успешно запущен"
    else
        echo "❌ Ошибка запуска. Проверьте: sudo systemctl status mprs"
    fi
fi

echo ""
echo "✨ Готово! Система обновлена и готова к работе."
