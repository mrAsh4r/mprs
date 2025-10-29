#!/bin/bash
# Быстрое обновление только кода без перенастройки

echo "🚀 Быстрое обновление MPRS..."

sudo systemctl stop mprs 2>/dev/null || true

# Копируем только Python файлы
for file in *.py; do
    if [[ -f "$file" ]]; then
        sudo cp "$file" /opt/mprs/src/
        echo "✅ $file"
    fi
done

# Перезапуск
sudo systemctl start mprs
sudo systemctl status mprs --no-pager

echo "🎉 Обновление завершено!"
