# Лабораторная работа №7: Безопасность микросервисов (JWT, API Gateway, RBAC, Rate Limiting)

Микросервисная система с централизованной аутентификацией на базе **JWT**, единой точкой входа **API Gateway**, ролевым контролем доступа (**RBAC**) во внутренних сервисах и защитой от перегрузки (**Rate Limiting**).

---

## Архитектура безопасности

```
 [ Клиент / Браузер ]
         │  Authorization: Bearer <JWT>
         ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │                     API GATEWAY (порт 8000)                     │
 │  1. Rate Limiting (100 req/15м общий, 5 req/15м /auth/login)    │
 │     Возвращает X-RateLimit-Limit / Remaining / Reset (или 429)  │
 │  2. Валидация JWT (подпись HS256, срок exp, 401 при ошибке)     │
 │  3. Извлечение claims и проброс заголовков:                     │
 │     X-User-Id: user-...  |  X-User-Role: admin/user             │
 └──────────┬───────────────────────┬───────────────────────┬──────┘
            │                       │ X-User-Id             │ X-User-Id
            │ /auth/*               │ X-User-Role           │ X-User-Role
            ▼                       ▼                       ▼
 ┌───────────────────┐   ┌───────────────────────┐   ┌────────────────────┐
 │   AUTH SERVICE    │   │    CATALOG SERVICE    │   │   ORDER SERVICE    │
 │    (порт 8001)    │   │      (порт 8002)      │   │    (порт 8003)     │
 │                   │   │                       │   │                    │
 │ POST /auth/register   │ GET /products (all)   │   │ POST /orders       │
 │   (хеш bcrypt)    │   │ POST /products (admin)│   │   (user & admin)   │
 │ POST /auth/login  │   │ DELETE /products/{id} │   │ GET /orders        │
 │   (выдача JWT)    │   │   (admin, иначе 403)  │   │   (свои / все)     │
 └───────────────────┘   └───────────────────────┘   └────────────────────┘
```

### Ключевые принципы реализации:
1. **Хеширование паролей:** `Auth Service` никогда не хранит пароли в открытом виде — используется `bcrypt` с уникальной солью.
2. **Секрет в переменных окружения:** `JWT_SECRET` не захардкожен в коде, а передается через `.env` / `docker-compose.yml`.
3. **Единая проверка JWT:** Валидация подписи и срока действия токена выполняется **только** в `API Gateway`. Внутренние сервисы доверяют проброшенным заголовкам `X-User-Id` и `X-User-Role` (подделанные клиентом заголовки `X-User-*` предварительно очищаются шлюзом).
4. **RBAC во внутренних сервисах:**
   - `Catalog Service`: создание и удаление товаров (`POST/DELETE /products`) доступно только роли `admin` (`403 Forbidden` для `user`).
   - `Order Service`: оформление заказов (`POST /orders`) доступно для любой авторизованной роли (`user` или `admin`).
5. **Rate Limiting в API Gateway:**
   - Общий лимит: `100` запросов за 15 минут с одного IP.
   - Строгий лимит для `POST /auth/login`: `5` попыток за 15 минут (защита от brute-force).
   - Обязательные заголовки в ответах: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.

---

## Структура проекта

```text
lab7-microservices/
├── api_gateway/
│   ├── app.py                # Единая точка входа: JWT middleware, прокси, дашборд (:8000)
│   ├── rate_limiter.py       # Ограничитель запросов (100/15м и 5/15м) с заголовками X-RateLimit-*
│   └── Dockerfile
├── auth_service/
│   ├── app.py                # Регистрация (bcrypt), логин и генерация JWT (:8001)
│   └── Dockerfile
├── catalog_service/
│   ├── app.py                # Сервис каталога товаров с RBAC проверкой admin (:8002)
│   └── Dockerfile
├── order_service/
│   ├── app.py                # Сервис заказов с RBAC проверкой user/admin (:8003)
│   └── Dockerfile
├── docker-compose.yml        # Контейнеризация всех 4 микросервисов
├── .env.example              # Пример переменных окружения (JWT_SECRET, лимиты)
├── run_local.py              # Локальный запуск всех сервисов без Docker
├── test_security.py          # Сквозной интеграционный автотест (401, 403, 200, 429)
└── requirements.txt          # Зависимости Python
```

---

## Быстрый запуск

### Вариант 1: Docker Compose (рекомендуется)
```bash
cp .env.example .env
docker compose up --build
```

### Вариант 2: Локальный запуск (без Docker)
```bash
pip install -r requirements.txt
python run_local.py
```

После запуска откройте интерактивный дашборд безопасности:  
👉 **`http://localhost:8000/`**

---

## Автоматическое тестирование всех сценариев

```bash
python test_security.py
```

Тест проверяет:
1. Регистрацию `user` и `admin`, наличие `bcrypt`-хеша в БД и выдачу валидного JWT.
2. Блокировку отсутствующего, поддельного и просроченного JWT с кодом **`401 Unauthorized`**.
3. RBAC: `POST /products` от `user` ➔ **`403 Forbidden`**, от `admin` ➔ **`201 Created`**, `POST /orders` от `user` ➔ **`201 Created`**.
4. Общий Rate Limit: 100 запросов ➔ `200 OK`, 101-й запрос ➔ **`429 Too Many Requests`** и `X-RateLimit-Remaining: 0`.
5. Строгий Rate Limit на `/auth/login`: 5 попыток ➔ `401`, 6-я попытка ➔ **`429 Too Many Requests`**.

---

## Команда проекта

Студенты группы **8И42**, ТПУ:
* **Довидович Александр Владимирович** — разработка `API Gateway` (JWT middleware, проброс `X-User-Id`/`X-User-Role`, обратный прокси, веб-дашборд), реализация `Rate Limiting` и инфраструктура (`docker-compose.yml`, `run_local.py`).
* **Петрушенко Даниил Евгеньевич** — разработка `Auth Service` (bcrypt + PyJWT), реализация `RBAC` в `Catalog Service` и `Order Service`, интеграционные тесты (`test_security.py`).
