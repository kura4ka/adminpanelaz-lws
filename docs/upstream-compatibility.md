# Совместимость с AdminPanelAZ

Исходная точка для сверки — коммит `d6ccd0098` оригинального проекта. [AdminPanelAZ](https://github.com/Kirito0098/AdminPanelAZ/tree/d6ccd0098b04463471332c244364ffbe05a3d156)

## Первый этап

Прототип на C и libwebsockets позволяет проверить раздачу готовых файлов React и затраты памяти HTTP-сервера. Для локальной проверки используются готовые файлы из `frontend/dist` исходного проекта. В оригинале Telegram Mini App собирается отдельно в `backend/app/static/tg_mini`. Возьмите обе сборки из одного коммита для дальнейшей проверки совместимости. Держите архивы, исходники оригинала, `.env`, базы и бэкапы за пределами этого репозитория. [Команды сборки](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/frontend/package.json#L7-L12) · [Артефакты CI](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/.github/workflows/ci.yml#L108-L145)

Загрузка стартовой страницы проверяет раздачу файлов. Для использования оригинального интерфейса с реальными данными потребуется совместимый API. До переноса авторизации запускайте прототип локально и используйте тестовые данные.

## Что проверять при переносе API

| Область | Контракт оригинала и проверка |
| --- | --- |
| Панель и портал | В одном наборе React-файлов работают прямые переходы на страницы панели, префикс `ACCESS_PATH` и ссылки `/p/...` на хосте портала, где API доступен от `/api`. Сверить маршрутизацию HTML, JS и неизвестных API-путей, а также ограничения по хосту. [Маршрутизация](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/backend/app/main.py#L571-L641) |
| Вход и файлы | Сверить JWT, ротацию refresh-cookie, статусы и поля ошибок, включая `409` при смене активного узла. Проверить, какие JS-чанки доступны до входа, правила выдачи закрытых чанков и заголовки кэша в панели и Mini App. Сверить заголовки и имена при скачивании профилей. [HTTP-клиент](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/frontend/src/api/http.ts#L171-L277) · [Панель](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/backend/app/services/frontend_assets.py#L107-L128) · [Mini App](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/backend/app/routers/tg_mini/static.py#L29-L84) |
| Live-обновления | Проверить одноразовые билеты через `/stream-ticket`, события SSE мониторинга, уведомлений, установки AWG2 и обновления Warper. Для WebSocket `/server-monitor/ws` сверить структуру и частоту сообщений, закрытие при отклонённом билете и переподключение клиента. [Клиент SSE](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/frontend/src/api/streamTicket.ts) · [WebSocket](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/backend/app/routers/server_monitor.py#L64-L124) |
| Данные и бэкапы | Проверить миграцию на копиях существующих SQLite и импорт архива с `data/adminpanel.db`, `data/cidr/cidr.db` и `env/.env`. Сверить восстановление ссылок портала, настроек и поддерживаемых файлов, а также откат после прерванного восстановления. Для крупных баз предусмотреть обработку через временные файлы с ограниченным буфером. [Формат и восстановление](https://github.com/Kirito0098/AdminPanelAZ/blob/d6ccd0098/backend/app/services/backup_manager.py#L190-L432) |

Для сверки запускайте одинаковую готовую сборку интерфейса с оригинальным backend и с портом на одной тестовой базе в отдельных копиях. Сравнивайте HTTP-ответы, файлы, события и состояние после записи. OpenAPI подходит для основных HTTP-контрактов, а cookie, выдачу чанков, SSE и WebSocket проверяйте отдельными сценариями.
