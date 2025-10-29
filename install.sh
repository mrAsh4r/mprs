#!/bin/bash

set -e

echo "=== MPRS Installation Script ==="

# Проверка root прав
if [[ $EUID -ne 0 ]]; then
   echo "Этот скрипт должен запускаться с правами root (sudo)" 
   exit 1
fi

# Установка системных пакетов
echo "Установка системных зависимостей..."
apt update
apt install -y python3 python3-venv python3-pip iptables libpcap-dev

# Создание пользователя mprs
if ! id "mprs" &>/dev/null; then
    echo "Создание пользователя mprs..."
    useradd -r -s /bin/false mprs
fi

# Создание каталогов
echo "Создание каталогов..."
mkdir -p /opt/mprs
mkdir -p /var/log/mprs
mkdir -p /etc/mprs

# Копирование файлов
echo "Копирование файлов..."
cp -r *.py /opt/mprs/
cp -r rules.yaml mprs.conf whitelist.txt /etc/mprs/
cp requirements.txt /opt/mprs/

# Создание виртуального окружения
echo "Создание виртуального окружения..."
cd /opt/mprs
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Права доступа
echo "Настройка прав доступа..."
chown -R mprs:mprs /opt/mprs
chown -R mprs:mprs /var/log/mprs
chown -R mprs:mprs /etc/mprs

# Права для захвата пакетов
setcap cap_net_raw,cap_net_admin+eip /opt/mprs/venv/bin/python

# Установка systemd сервиса
echo "Установка systemd сервиса..."
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
ExecStart=/opt/mprs/venv/bin/python main.py
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/mprs /etc/mprs
PrivateTmp=yes

# Capabilities for packet capture
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo "=== Установка завершена ==="
echo "Для запуска: systemctl start mprs"
echo "Для автозапуска: systemctl enable mprs"
