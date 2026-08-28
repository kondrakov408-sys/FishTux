# TuxFind — Поисковый Сервис на Go 🐧

Быстрый, приватный метапоисковый сервис без сохранения логов и персональных данных.

## 🚀 Возможности
- **Стандартная библиотека Go (`net/http`)**: нулевой оверхед, отсутствие лишних внешних зависимостей.
- **Параллельный опрос источников**: Wikipedia OpenSearch API + DuckDuckGo Web.
- **Строгий тайм-аут**: не более 3 секунд (`context.WithTimeout`).
- **Безопасность и Приватность**:
  - Санитизация входящих запросов.
  - Zero-Logs: IP-адреса и история запросов не логируются в stdout/диск.
  - Поддержка CORS для обращения из браузера (Tauri / Localhost).

## 📦 Сборка и запуск

```bash
cd TuxFind
# Сборка
go build -o tuxfind main.go

# Запуск
./tuxfind
```

Сервер запустится на `http://localhost:8080`.

## 🔍 Пример API запроса

```bash
curl -s "http://localhost:8080/api/v1/search?q=Arch+Linux"
```

Пример JSON ответа:
```json
{
  "query": "Arch Linux",
  "took_ms": 234,
  "results": [
    {
      "title": "Arch Linux",
      "url": "https://en.wikipedia.org/wiki/Arch_Linux",
      "snippet": "Arch Linux is an independently developed, x86-64 general-purpose Linux distribution...",
      "source": "wikipedia"
    },
    {
      "title": "Arch Linux",
      "url": "https://archlinux.org",
      "snippet": "A lightweight and flexible Linux distribution that tries to Keep It Simple.",
      "source": "web"
    }
  ]
}
```
