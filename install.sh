#!/bin/bash

set -e

echo "=== MPRS Installation Script ==="

# Проверка root прав
if [[ $EUID -ne 0 ]]; then
   echo "Этот скрипт должен запускаться с правами root (sudo)" 
   exit 1
fi

# Проверка дистрибутива
if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
    PKG_UPDATE="apt update"
    PKG_INSTALL="apt install -y"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum update -y"
    PKG_INSTALL="yum install -y"
else
    echo "Неподдерживаемый дистрибутив. Требуется apt или yum."
    exit 1
fi

# Установка системных пакетов
echo "Установка системных зависимостей..."
$PKG_UPDATE

if [[ "$PKG_MANAGER" == "apt" ]]; then
    $PKG_INSTALL python3 python3-venv python3-pip iptables libpcap-dev libcap2-bin
else
    $PKG_INSTALL python3 python3-pip iptables libpcap-devel libcap
fi

# Создание пользователя mprs
if ! id "mprs" &>/dev/null; then
    echo "Создание пользователя mprs..."
    useradd -r -s /bin/false -d /opt/mprs mprs
fi

# Создание каталогов
echo "Создание каталогов..."
mkdir -p /opt/mprs/{src,config,logs}
mkdir -p /var/log/mprs
mkdir -p /etc/mprs

# Копирование файлов (убедитесь, что файлы существуют в текущем каталоге)
echo "Копирование файлов..."

# Проверяем наличие Python файлов
for file in main.py sniffer.py analyzer.py blocker.py notifier.py logger.py web_ui.py utils.py; do
    if [[ -f "$file" ]]; then
        cp "$file" /opt/mprs/src/
    else
        echo "ВНИМАНИЕ: Файл $file не найден в текущем каталоге"
    fi
done

# Проверяем наличие конфигурационных файлов
for file in rules.yaml mprs.conf whitelist.txt; do
    if [[ -f "$file" ]]; then
        cp "$file" /etc/mprs/
    else
        echo "ВНИМАНИЕ: Файл $file не найден в текущем каталоге"
    fi
done

# Создание requirements.txt если не существует
if [[ ! -f "requirements.txt" ]]; then
    echo "Создание requirements.txt..."
    cat > /opt/mprs/requirements.txt << 'EOF'
scapy>=2.4.5
flask>=2.3.0
pyyaml>=6.0
requests>=2.28.0
psutil>=5.9.0
EOF
else
    cp requirements.txt /opt/mprs/
fi

# Создание виртуального окружения
echo "Создание виртуального окружения..."
cd /opt/mprs
python3 -m venv venv

# Активация и установка пакетов
echo "Установка Python пакетов..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

# Права доступа
echo "Настройка прав доступа..."
chown -R mprs:mprs /opt/mprs
chown -R mprs:mprs /var/log/mprs
chown -R mprs:mprs /etc/mprs

# Альтернативный способ настройки прав для захвата пакетов
echo "Настройка прав для захвата пакетов..."

# Метод 1: setcap (предпочтительный)
if command -v setcap &> /dev/null; then
    if setcap cap_net_raw,cap_net_admin+eip /opt/mprs/venv/bin/python3 2>/dev/null; then
        echo "✓ setcap успешно применен к Python"
        CAPABILITY_METHOD="setcap"
    else
        echo "⚠ setcap не удался, пробуем альтернативные методы..."
        CAPABILITY_METHOD="sudo"
    fi
else
    echo "⚠ setcap недоступен, используем sudo метод"
    CAPABILITY_METHOD="sudo"
fi

# Создание обертки для запуска с правами (если setcap не работает)
if [[ "$CAPABILITY_METHOD" == "sudo" ]]; then
    echo "Создание sudo обертки..."
    cat > /opt/mprs/start_mprs.sh << 'EOF'
#!/bin/bash
cd /opt/mprs
exec /opt/mprs/venv/bin/python3 src/main.py
EOF
    chmod +x /opt/mprs/start_mprs.sh
    chown mprs:mprs /opt/mprs/start_mprs.sh
    
    # Добавляем mprs в sudoers для запуска без пароля
    echo "mprs ALL=(ALL) NOPASSWD: /opt/mprs/start_mprs.sh" > /etc/sudoers.d/mprs-packet-capture
    chmod 440 /etc/sudoers.d/mprs-packet-capture
fi

# Установка systemd сервиса
echo "Установка systemd сервиса..."
if [[ "$CAPABILITY_METHOD" == "setcap" ]]; then
    # Сервис с setcap capabilities
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
    # Сервис с sudo wrapper
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

# Создание __init__.py файла в src
touch /opt/mprs/src/__init__.py

# Создание default конфигураций если их нет
if [[ ! -f /etc/mprs/mprs.conf ]]; then
    echo "Создание базовой конфигурации..."
    cat > /etc/mprs/mprs.conf << 'EOF'
[GENERAL]
interface = eth0
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
fi

if [[ ! -f /etc/mprs/whitelist.txt ]]; then
    cat > /etc/mprs/whitelist.txt << 'EOF'
# MPRS Whitelist
127.0.0.1
::1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF
fi

if [[ ! -f /etc/mprs/rules.yaml ]]; then
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
  regex: "sqlmap|nikto|curl.*bot|python-requests|masscan|nmap|gobuster"
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
EOF
fi

# Финальная настройка прав
chown -R mprs:mprs /etc/mprs
chmod 755 /etc/mprs
chmod 644 /etc/mprs/*

systemctl daemon-reload

echo "=== Установка завершена ==="
echo ""
if [[ "$CAPABILITY_METHOD" == "setcap" ]]; then
    echo "✓ Используется setcap для прав захвата пакетов"
else
    echo "✓ Используется sudo wrapper для прав захвата пакетов"
fi
echo ""
echo "Для запуска:"
echo "  sudo systemctl start mprs"
echo ""
echo "Для автозапуска:"
echo "  sudo systemctl enable mprs"
echo ""
echo "Проверка статуса:"
echo "  sudo systemctl status mprs"
echo ""
echo "Веб-интерфейс будет доступен: http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "Логи:"
echo "  sudo journalctl -u mprs -f"
echo "  sudo tail -f /var/log/mprs/events.json"
