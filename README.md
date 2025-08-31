# Everyday Site — admin-managed shield

## Что внутри
- `public/` — веб-корень. `index.php` подключает `shield/guard.php`.
- `public/shield/` — JS-защита (PoW) + проверка на PHP. Настройки читаются из `storage/config.json`.
- `public/admin-*/panel.php` — админка с вкладкой «Настройки» (Shield/DDoS/Logger).
- `storage/` — файлы банов/логов и `config.json` (не доступно снаружи).
- Dockerfile — DocumentRoot=/public, `mod_remoteip`, создаёт пустые файлы в `storage/`.
- `apache-remoteip.conf` — конфиг для реального IP за Cloudflare.
- `entrypoint.sh` — для Render ($PORT).

## Первое включение
- Задай в Render `ADMIN_USER` и `ADMIN_PASS_HASH` (пароль через `password_hash`).
- В админке можно править Shield/DDoS/Logger. Файл `storage/config.json` создаётся автоматически.

## Частые настройки
- Shield Mode: low/medium/high (в админке).
- TTL/Window и привязки к UA/IP — тоже в админке.
- DDoS лимиты и honeypot — в админке, но на практике выноси это в Cloudflare (WAF/Rate Limit).
