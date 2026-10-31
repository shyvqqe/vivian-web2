# Vivian Web 2.0 — первая рабочая интеграция

## Содержимое
- `site/`: прежний лендинг и новый `/dashboard.html`, `/docs.html`, SEO файлы.
- `server/`: Flask-приложение с OAuth2 Discord (`identify`) и read-only API XP из Supabase.
- `bot-patch/server.py`: **необязательная** замена `app/server.py` бота для публичного числа серверов.

## Запуск
1. Развернуть `server/` **вместе с `site/` в одном репозитории** как отдельный веб-сервис Render. Root Directory оставить в корне репозитория.
2. Build Command: `pip install -r server/requirements.txt`; Start Command: `gunicorn --chdir server app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4`.
3. В Render настроить переменные `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `PUBLIC_BASE_URL=https://vivian.lat`, `DATABASE_URL` (тот же Postgres, что и у бота). Секреты не коммитить в GitHub.
4. В Discord Developer Portal → OAuth2 → Redirects указать `https://vivian.lat/auth/callback` **точно**. Настроить DNS vivian.lat на новый веб-сервис и HTTPS. Перед переключением домена испытать staging с его собственным PUBLIC_BASE_URL и redirect URL.
5. Опционально: заменить `app/server.py` бота файлом из `bot-patch/server.py`, перезапустить бот. Указать веб-сервису `BOT_PUBLIC_STATS_URL=https://<bot-host>/api/public/stats` (нужен только для реального количества серверов). Этот URL показывает только число серверов, без имен и ID.
6. Проверить вход → `/api/me` → выход; убедиться, что чужие профили недоступны, и проверить fallback статистики.

## Безопасность и ограничения
- OAuth: `identify`, одноразовый `state`, HttpOnly Secure SameSite=Lax cookie, случайный opaque session ID, срок 12 часов, без клиентского токена; Discord access token **не сохраняется**.
- Сессии хранятся в памяти сервиса и пропадут при перезапуске. Работает при `--workers 1`; для нескольких инстансов нужен Redis / server-side persistent session store.
- `/api/me` показывает только XP текущего авторизованного пользователя. Нет эндпоинта для произвольного user_id.
- В базе таблица `public.user_xp` хранит XP глобально, а не по серверам. Поэтому рейтинг относится к всем записям в базе, не к выбранному Discord-серверу.
- Стены, краши, личные сообщения **не раскрываются** и не синхронизированы. Необходимо согласовать ACL и существующее хранилище до их внедрения.
- Нужна настройка реального домена: статический сайт без Python-сервера не выполнит OAuth/API.
- Для нескольких доменов (esil.life и vivian.lat) использовать один канонический origin для сессии или раздельные redirect URL; здесь выбран vivian.lat.
- Избегайте раскрытия DATABASE_URL, CLIENT_SECRET и cookie через скриншоты и журналы.
- Полный сквозной тест на реальном Discord и Supabase в этом окружении невозможен без доступа к ключам/деплою.
