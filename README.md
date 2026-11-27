# AdminPanelAZ LWS

Перенос AdminPanelAZ на C и libwebsockets со встроенным интерфейсом на HTML, CSS и JavaScript. Текущая ветка предназначена для стендовой проверки. Состояние функций и условия единого выпуска перечислены в [матрице совместимости](docs/upstream-compatibility.md).

## Сборка на Ubuntu 24.04 или Debian 13

GitHub Actions отдельно собирает и проверяет прототип на Ubuntu 24.04 и Debian 13.

Установите зависимости и соберите прототип из каталога репозитория. Команды `apt-get` выполняйте от root или через `sudo`.

```sh
sudo apt-get update
sudo apt-get install -y git build-essential cmake libwebsockets-dev libssl-dev libsqlite3-dev libarchive-dev libcurl4-openssl-dev libcrypt-dev zlib1g-dev openssl curl
git clone https://github.com/kura4ka/adminpanelaz-lws.git &&
cd adminpanelaz-lws &&
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release &&
cmake --build build --parallel 1
```

Если репозиторий уже клонирован, начните с перехода в его каталог.

## Запуск

```sh
export APAZ_AUTH_TOKEN="$(openssl rand -hex 24)"
./build/adminpanelaz-lws --bind 127.0.0.1 --port 8000 --data-dir ./data --auth-db ./data/auth.db
```

Откройте `http://127.0.0.1:8000/` и войдите как `admin`, используя начальный пароль `APAZ_AUTH_TOKEN`. Для ручного подключения источников передайте `--openvpn-status` с путём к каждому файлу статуса OpenVPN и `--wireguard-status` с путём к снимку WireGuard. В счётчик активных входят пиры с рукопожатием за последние 180 секунд. Для публикации встроенной панели в подкаталоге используйте `--access-path /subdir`.

### Установка на тестовом домене

Направьте A-запись домена на VPS и выпустите сертификат Certbot для него. Доступ по HTTPS использует TCP 443, а standalone-проверка Certbot — TCP 80. Из каталога проекта после сборки установите службы:

```sh
sudo sh deploy/install-systemd.sh panel.example.org
sudo sed -n 's/^APAZ_AUTH_TOKEN=//p' /etc/adminpanelaz-lws/auth.env
```

Откройте `https://panel.example.org/`. При первом запуске установщик создаёт учётную запись `admin` с начальным паролем из `APAZ_AUTH_TOKEN`. После входа пароль можно поменять в панели. Токен также поддерживает прежний режим просмотра мониторинга. Для управления архивами и скачивания файлов требуется вход по паролю.

Установщик включает обновление снимков OpenVPN и WireGuard через systemd каждые 10 секунд. Веб-процесс запускается под отдельным пользователем и имеет доступ на чтение к каталогу клиентских профилей через отдельное монтирование systemd. Certbot обновляет сертификат своим таймером и перезапускает панель после продления.

Для просмотра списков AntiZapret добавьте `APAZ_SNAPSHOT_VPN_LISTS=1` перед запуском установщика, например `sudo env APAZ_SNAPSHOT_VPN_LISTS=1 sh deploy/install-systemd.sh panel.example.org`. Таймер обновляет отдельные снимки известных списков маршрутизации и RPZ. При ручном запуске укажите доверенный каталог списков через `--config-dir`, а каталог Lua-политик Knot Resolver через `--knot-dir`. Редактор открывает файлы для чтения, предел на файл составляет 32 КиБ.

Передайте `--ui-dir /path/to/frontend/dist`, чтобы включить раздачу файлов из доверенной сборки React. Страница `index.html` загружается при запуске с лимитом 32 КиБ. Ссылки Vite на `./assets/` преобразуются в `/assets/` для прямого перехода на вложенные страницы. Для HTTPS добавьте `--tls-cert /path/to/cert.pem --tls-key /path/to/key.pem`. Без сертификата сервер слушает только IPv4 loopback. Сервер поддерживает HTTP/1.1 и до 12 одновременных сессий SSE/WS.

Если HTTPS завершает обратный прокси, передайте `--public-origin https://panel.example.org` и сохраняйте исходный заголовок `Host` при проксировании на локальный HTTP-порт. В этом режиме панель проверяет заданный `Origin` и выставляет атрибут `Secure` у cookie сеанса.

| Метод и путь | Что делает |
| --- | --- |
| `GET /api/health` | Публичная проверка запуска |
| `GET /api/monitor` | Текущие счётчики процесса |
| `GET /api/monitor/events` | SSE с выборкой каждые две секунды |
| `GET /api/monitor/ws` | WebSocket с выборкой каждые две секунды |
| `POST /api/backups/upload` | Записывает `application/octet-stream` из запроса с `Content-Length` в `data/backups/` |

Передавайте `Authorization: Bearer $APAZ_AUTH_TOKEN` для мониторинга. При запуске с `--auth-db` остальные административные API требуют сеанс администратора. Загрузка завершает переименование временного файла после получения всего тела. Отключение клиента удаляет незавершённый временный файл.

```sh
curl -H "Authorization: Bearer $APAZ_AUTH_TOKEN" http://127.0.0.1:8000/api/monitor
curl -N -H "Authorization: Bearer $APAZ_AUTH_TOKEN" http://127.0.0.1:8000/api/monitor/events
```

- Нативные учётные записи поддерживают роли, принудительную смену пароля, IP-списки, ограничение входа и CAPTCHA. Для настройки TOTP с резервными кодами задайте постоянный `APAZ_SECURITY_KEY` из 64 шестнадцатеричных символов. Храните его отдельно от файлов резервных копий. `APAZ_IP_ALLOWLIST` принимает CIDR через запятую, `APAZ_TRUSTED_PROXY_IPS` принимает адреса доверенных прокси.
- Для локальных изменений клиентов используется отдельная socket-activated служба. VPN- и прокси-агенты подключаются по HTTP, HTTPS или mTLS. [Помощник VPN](docs/local-vpn-helper.md) · [Агенты узлов](docs/node-agents.md)
- Старые ссылки портала можно обслуживать на настроенном в снимке отдельном хосте. Для этого передайте `--portal-db` и `--portal-profiles-dir` с согласованными копиями legacy-БД и локальных файлов профилей. [Контракты портала](docs/upstream-compatibility.md#внешние-контракты-для-тестов-совместимости)
- Импорт запускается на отдельных локальных копиях. `adminpanelaz-migration` подготавливает `tar.gz` и `APAZBK1`, выгружает состояние выключенной нативной панели и переносит отдельные данные из оригинала. Для CIDR и истории используются `adminpanelaz-cidr-import --legacy` и `adminpanelaz-history-migration`. Офлайн-снимок всего состояния сохраняет базу MFA вместе с учётными записями. Веб-архив учётных записей содержит только базу входа. [Telegram](docs/telegram.md) · [Матрица миграции](docs/upstream-compatibility.md)

## Проверка

```sh
python3 tests/smoke.py ./build/adminpanelaz-lws
sh tests/module_smoke.sh ./build
```

Для HTTPS используйте те же тесты с `--tls-cert` и `--tls-key` и отдельной парой для стенда. Тесты проверяют раздачу SPA, авторизацию, потоки и приём файла.

На тестовом Linux со systemd и cgroup v2 этот сценарий запускает отдельный сервис с `MemoryMax=20M` и `MemorySwapMax=0` на дисковой файловой системе. Он проверяет интерфейс и вход, открывает три SSE и два WebSocket-подключения, обновляет снимки VPN, создаёт архив и передаёт 48 МиБ по HTTPS в обоих направлениях. В отчёт входят пик памяти, счётчики cgroup и задержки API.

```sh
python3 tests/memory_budget.py ./build/adminpanelaz-lws /path/to/test.crt /path/to/test.key
```
