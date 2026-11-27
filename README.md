# AdminPanelAZ LWS

Прототип сервера AdminPanelAZ на C и libwebsockets. Принимает готовую сборку React через `--ui-dir`, отдаёт метрики самого процесса по JSON, SSE и WebSocket и принимает файлы до 200 МиБ порциями на диск. Прототип рассчитан на локальную проверку с тестовыми данными. [План совместимости с оригиналом](docs/upstream-compatibility.md)

## Сборка на Ubuntu 24.04 или Debian 13

GitHub Actions отдельно собирает и проверяет прототип на Ubuntu 24.04 и Debian 13.

```sh
sudo apt-get install build-essential cmake libwebsockets-dev openssl python3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Запуск

```sh
export APAZ_AUTH_TOKEN="$(openssl rand -hex 24)"
./build/adminpanelaz-lws --bind 127.0.0.1 --port 8000 --data-dir ./data
```

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

Маршруты прототипа служат для проверки транспорта. Вход, рабочие экраны React, обычные и зашифрованные бэкапы оригинала, обновление CIDR и подключение к VPN-узлам требуют переноса соответствующего API и бизнес-логики.

## Проверка

```sh
python3 tests/smoke.py ./build/adminpanelaz-lws
```

Для HTTPS используйте те же тесты с `--tls-cert` и `--tls-key` и отдельной парой для стенда. Тесты проверяют раздачу SPA, авторизацию, потоки и приём файла. Бюджет 20 МиБ оценивается отдельно в Linux по `MemoryPeak` сервиса при нескольких открытых потоках и большой загрузке.
