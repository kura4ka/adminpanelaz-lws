# AdminPanelAZ LWS

Перенос AdminPanelAZ на C и libwebsockets. Первый раздел «Мониторинг» встроен в бинарник и работает на HTML, CSS и JavaScript. Он показывает ресурсы Linux, сетевые интерфейсы, клиентские подключения OpenVPN и состояние пиров WireGuard. [План переноса остального функционала](docs/upstream-compatibility.md)

## Сборка на Ubuntu 24.04 или Debian 13

GitHub Actions отдельно собирает и проверяет прототип на Ubuntu 24.04 и Debian 13.

Установите зависимости и соберите прототип из каталога репозитория. Команды `apt-get` выполняйте от root или через `sudo`.

```sh
sudo apt-get update
sudo apt-get install -y git build-essential cmake libwebsockets-dev libssl-dev libsqlite3-dev libarchive-dev zlib1g-dev openssl
git clone https://github.com/kura4ka/adminpanelaz-lws.git &&
cd adminpanelaz-lws &&
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release &&
cmake --build build --parallel 1
```

Если репозиторий уже клонирован, начните с перехода в его каталог.

## Запуск

```sh
export APAZ_AUTH_TOKEN="$(openssl rand -hex 24)"
./build/adminpanelaz-lws --bind 127.0.0.1 --port 8000 --data-dir ./data
```

Откройте `http://127.0.0.1:8000/` и введите значение `APAZ_AUTH_TOKEN`. Для ручного подключения источников передайте `--openvpn-status` с путём к каждому файлу статуса OpenVPN и `--wireguard-status` с путём к снимку WireGuard. Состояние и время последнего рукопожатия WireGuard отображаются отдельно. В счётчик активных входят пиры с рукопожатием за последние 180 секунд.

### Публикация на своём домене

Направьте A-запись домена на VPS и выпустите сертификат Certbot для него. Доступ по HTTPS использует TCP 443, а standalone-проверка Certbot — TCP 80. Из каталога проекта после сборки установите службы:

```sh
sudo sh deploy/install-systemd.sh panel.example.org
sudo sed -n 's/^APAZ_AUTH_TOKEN=//p' /etc/adminpanelaz-lws/auth.env
```

Откройте `https://panel.example.org/`. При первом запуске установщик создаёт учётную запись `admin` с начальным паролем из `APAZ_AUTH_TOKEN`. После входа пароль можно поменять в панели. Токен также поддерживает прежний режим просмотра мониторинга. Для управления архивами и скачивания файлов требуется вход по паролю.

Установщик включает обновление снимков OpenVPN и WireGuard через systemd каждые 10 секунд. Веб-процесс запускается под отдельным пользователем и имеет доступ на чтение к каталогу клиентских профилей через отдельное монтирование systemd. Certbot обновляет сертификат своим таймером и перезапускает панель после продления.

Передайте `--ui-dir /path/to/frontend/dist`, чтобы включить раздачу файлов из доверенной сборки React. Страница `index.html` загружается при запуске с лимитом 32 КиБ. Ссылки Vite на `./assets/` преобразуются в `/assets/` для прямого перехода на вложенные страницы. Для HTTPS добавьте `--tls-cert /path/to/cert.pem --tls-key /path/to/key.pem`. Без сертификата сервер слушает только IPv4 loopback. Сервер поддерживает HTTP/1.1 и до 12 одновременных сессий SSE/WS.

| Метод и путь | Что делает |
| --- | --- |
| `GET /api/health` | Публичная проверка запуска |
| `GET /api/monitor` | Текущие счётчики процесса |
| `GET /api/monitor/events` | SSE с выборкой каждые две секунды |
| `GET /api/monitor/ws` | WebSocket с выборкой каждые две секунды |
| `POST /api/backups/upload` | Записывает `application/octet-stream` из запроса с `Content-Length` в `data/backups/` |

Для операций кроме проверки запуска передавайте `Authorization: Bearer $APAZ_AUTH_TOKEN`. Загрузка завершает переименование временного файла после получения всего тела. Отключение клиента удаляет незавершённый временный файл.

```sh
curl -H "Authorization: Bearer $APAZ_AUTH_TOKEN" http://127.0.0.1:8000/api/monitor
curl -N -H "Authorization: Bearer $APAZ_AUTH_TOKEN" http://127.0.0.1:8000/api/monitor/events
```

На текущем этапе доступны мониторинг локального VPS, один локальный администратор с хранимыми в SQLite сессиями, просмотр и скачивание существующих профилей AntiZapret и загрузка, просмотр содержимого и скачивание бэкапов. Новая нативная копия содержит SQLite-базу учётных записей C-панели без действующих сессий. Для старого формата `APAZBK1` панель определяет, что архив зашифрован. Изменение VPN-клиентов, удалённые узлы, миграция учётных записей оригинала, Telegram, CIDR и восстановление бэкапов предстоит перенести.

## Проверка

```sh
python3 tests/smoke.py ./build/adminpanelaz-lws
```

Для HTTPS используйте те же тесты с `--tls-cert` и `--tls-key` и отдельной парой для стенда. Тесты проверяют раздачу SPA, авторизацию, потоки и приём файла.

На тестовом Linux с systemd и cgroup v2 этот сценарий запускает прототип в отдельном сервисе с `MemoryMax=20M` и `MemorySwapMax=0`. Он открывает три SSE и два WebSocket-подключения, загружает 48 МиБ по HTTPS и выводит пик памяти сервиса и счётчики OOM.

```sh
python3 tests/memory_budget.py ./build/adminpanelaz-lws /path/to/test.crt /path/to/test.key
```
