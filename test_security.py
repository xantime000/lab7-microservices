import os
import sys
import uuid
import datetime
import jwt
import requests
from dotenv import load_dotenv

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

load_dotenv()

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")
JWT_SECRET = os.getenv("JWT_SECRET", "tpu_lab7_jwt_secret_key_8i42_2026_secure")

def sep(title: str):
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)

def main():
    sep("ТЕСТИРОВАНИЕ ЛАБОРАТОРНОЙ РАБОТЫ №7: JWT + GATEWAY + RBAC + RATE LIMITING")

    # 1. Проверка доступности Gateway
    print("\n[Шаг 1] Проверка доступности API Gateway...")
    try:
        r_health = requests.get(f"{GATEWAY_URL}/health", timeout=3)
        assert r_health.status_code == 200
        print(f"  -> API Gateway (порт 8000): HTTP 200 [OK] | {r_health.json()}")
    except Exception as e:
        print(f"[ОШИБКА] Не удалось подключиться к API Gateway: {e}")
        print("Запустите сервисы через 'docker compose up --build' или 'python run_local.py'")
        sys.exit(1)

    # Сбросим счетчики перед прогоном тестов
    requests.post(f"{GATEWAY_URL}/gateway/reset-limits")

    suffix = uuid.uuid4().hex[:6]
    user_email = f"student_{suffix}@tpu.ru"
    admin_email = f"admin_{suffix}@tpu.ru"

    # -------------------------------------------------------------------------
    # ЭТАП 1: РЕГИСТРАЦИЯ (BCRYPT) И УСПЕШНЫЙ ЛОГИН (JWT)
    # -------------------------------------------------------------------------
    sep("ЭТАП 1: РЕГИСТРАЦИЯ (BCRYPT) И ЛОГИН С ПОЛУЧЕНИЕМ JWT")

    r_reg_u = requests.post(f"{GATEWAY_URL}/auth/register", json={
        "email": user_email, "password": "userPass123", "role": "user"
    })
    assert r_reg_u.status_code == 201, f"Ошибка регистрации user: {r_reg_u.text}"
    print(f"  -> Зарегистрирован user:  {user_email} (HTTP 201)")

    r_reg_a = requests.post(f"{GATEWAY_URL}/auth/register", json={
        "email": admin_email, "password": "adminPass123", "role": "admin"
    })
    assert r_reg_a.status_code == 201, f"Ошибка регистрации admin: {r_reg_a.text}"
    print(f"  -> Зарегистрирован admin: {admin_email} (HTTP 201)")

    # Проверяем, что пароль в БД захеширован bcrypt ($2b$...)
    users_list = requests.get(f"{GATEWAY_URL}/auth/users").json()
    u_row = next(u for u in users_list if u["email"] == user_email)
    assert u_row["password_hash"].startswith("$2b$") and "userPass123" not in u_row["password_hash"]
    print(f"  -> Проверка bcrypt-хеша:  {u_row['password_hash'][:29]}... [OK, пароль не в открытом виде]")

    # Логин user
    r_login_u = requests.post(f"{GATEWAY_URL}/auth/login", json={
        "email": user_email, "password": "userPass123"
    })
    assert r_login_u.status_code == 200, f"Ошибка логина user: {r_login_u.text}"
    user_token = r_login_u.json()["access_token"]
    decoded_u = jwt.decode(user_token, JWT_SECRET, algorithms=["HS256"])
    print(f"  -> Получен JWT (user):    {user_token[:40]}...")
    print(f"  -> Декодированный payload: {decoded_u}")
    assert decoded_u["role"] == "user" and "sub" in decoded_u and "exp" in decoded_u

    # Логин admin
    r_login_a = requests.post(f"{GATEWAY_URL}/auth/login", json={
        "email": admin_email, "password": "adminPass123"
    })
    assert r_login_a.status_code == 200, f"Ошибка логина admin: {r_login_a.text}"
    admin_token = r_login_a.json()["access_token"]
    decoded_a = jwt.decode(admin_token, JWT_SECRET, algorithms=["HS256"])
    print(f"  -> Получен JWT (admin):   {admin_token[:40]}...")
    print(f"  -> Декодированный payload: {decoded_a}")
    assert decoded_a["role"] == "admin"

    # -------------------------------------------------------------------------
    # ЭТАП 2: ЗАЩИТА ОТ НЕВАЛИДНЫХ И ПРОСРОЧЕННЫХ ТОКЕНОВ (401 UNAUTHORIZED)
    # -------------------------------------------------------------------------
    sep("ЭТАП 2: ЗАЩИТА ОТ НЕВАЛИДНЫХ / ПРОСРОЧЕННЫХ ТОКЕНОВ (401 UNAUTHORIZED)")

    r_no_tok = requests.get(f"{GATEWAY_URL}/products")
    print(f"  1. Запрос без токена:         HTTP {r_no_tok.status_code} | {r_no_tok.json()}")
    assert r_no_tok.status_code == 401

    r_bad_tok = requests.get(f"{GATEWAY_URL}/products", headers={"Authorization": "Bearer fake.invalid.jwt"})
    print(f"  2. Поддельный токен:          HTTP {r_bad_tok.status_code} | {r_bad_tok.json()}")
    assert r_bad_tok.status_code == 401

    expired_token = jwt.encode({
        "sub": decoded_u["sub"],
        "role": "user",
        "exp": int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)).timestamp())
    }, JWT_SECRET, algorithm="HS256")
    r_exp_tok = requests.get(f"{GATEWAY_URL}/products", headers={"Authorization": f"Bearer {expired_token}"})
    print(f"  3. Просроченный токен (exp):  HTTP {r_exp_tok.status_code} | {r_exp_tok.json()}")
    assert r_exp_tok.status_code == 401
    print("  -> [✓] Gateway корректно блокирует невалидные и просроченные токены с кодом 401!")

    # -------------------------------------------------------------------------
    # ЭТАП 3: ПРОВЕРКА RBAC ВО ВНУТРЕННИХ СЕРВИСАХ (403 FORBIDDEN vs 200/201 OK)
    # -------------------------------------------------------------------------
    sep("ЭТАП 3: ПРОВЕРКА RBAC В CATALOG SERVICE И ORDER SERVICE")

    u_headers = {"Authorization": f"Bearer {user_token}"}
    a_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. user -> GET /products (OK)
    r_list_u = requests.get(f"{GATEWAY_URL}/products", headers=u_headers)
    print(f"  1. user  -> GET /products:    HTTP {r_list_u.status_code} (товаров: {len(r_list_u.json()['items'])})")
    assert r_list_u.status_code == 200

    # 2. user -> POST /products (403 Forbidden!)
    r_create_u = requests.post(f"{GATEWAY_URL}/products", headers=u_headers, json={
        "name": "Запрещенный товар", "price": 5000.0, "stock": 1
    })
    print(f"  2. user  -> POST /products:   HTTP {r_create_u.status_code} | {r_create_u.json()}")
    assert r_create_u.status_code == 403

    # 3. admin -> POST /products (201 Created!)
    r_create_a = requests.post(f"{GATEWAY_URL}/products", headers=a_headers, json={
        "name": "Смартфон Pixel 9 Pro", "price": 89000.0, "stock": 7
    })
    print(f"  3. admin -> POST /products:   HTTP {r_create_a.status_code} | ID={r_create_a.json()['product']['id']}")
    assert r_create_a.status_code == 201
    created_prod_id = r_create_a.json()["product"]["id"]

    # 4. user -> DELETE /products/{id} (403 Forbidden!)
    r_del_u = requests.delete(f"{GATEWAY_URL}/products/{created_prod_id}", headers=u_headers)
    print(f"  4. user  -> DELETE /products: HTTP {r_del_u.status_code} | {r_del_u.json()}")
    assert r_del_u.status_code == 403

    # 5. admin -> DELETE /products/{id} (200 OK!)
    r_del_a = requests.delete(f"{GATEWAY_URL}/products/{created_prod_id}", headers=a_headers)
    print(f"  5. admin -> DELETE /products: HTTP {r_del_a.status_code} | {r_del_a.json()['message']}")
    assert r_del_a.status_code == 200

    # 6. user -> POST /orders (201 Created — доступно любой авторизованной роли)
    r_ord_u = requests.post(f"{GATEWAY_URL}/orders", headers=u_headers, json={
        "product_id": "prod-1", "quantity": 1, "total_amount": 145000.0
    })
    print(f"  6. user  -> POST /orders:     HTTP {r_ord_u.status_code} | OrderID={r_ord_u.json()['order']['order_id']}")
    assert r_ord_u.status_code == 201
    print("  -> [✓] RBAC во всех внутренних сервисах работает безупречно!")

    # -------------------------------------------------------------------------
    # ЭТАП 4: RATE LIMITING (100 ЗАПРОСОВ -> 101-Й = 429 TOO MANY REQUESTS)
    # -------------------------------------------------------------------------
    sep("ЭТАП 4: RATE LIMITING В API GATEWAY (100 ЗАПРОСОВ / 15 МИН -> 429)")

    requests.post(f"{GATEWAY_URL}/gateway/reset-limits")
    for i in range(1, 101):
        r = requests.get(f"{GATEWAY_URL}/products", headers=u_headers)
        assert r.status_code == 200, f"Запрос #{i} неожиданно вернул {r.status_code}"
        if i in (1, 50, 100):
            print(
                f"  Запрос #{i:3d}: HTTP {r.status_code} | "
                f"X-RateLimit-Limit={r.headers.get('X-RateLimit-Limit')}, "
                f"X-RateLimit-Remaining={r.headers.get('X-RateLimit-Remaining')}, "
                f"X-RateLimit-Reset={r.headers.get('X-RateLimit-Reset')}"
            )

    # 101-й запрос должен быть заблокирован с кодом 429
    r_101 = requests.get(f"{GATEWAY_URL}/products", headers=u_headers)
    print(
        f"  Запрос #101: HTTP {r_101.status_code} | "
        f"X-RateLimit-Limit={r_101.headers.get('X-RateLimit-Limit')}, "
        f"X-RateLimit-Remaining={r_101.headers.get('X-RateLimit-Remaining')}, "
        f"X-RateLimit-Reset={r_101.headers.get('X-RateLimit-Reset')}"
    )
    print(f"  Тело ответа 429: {r_101.json()}")
    assert r_101.status_code == 429
    assert r_101.headers.get("X-RateLimit-Limit") == "100"
    assert r_101.headers.get("X-RateLimit-Remaining") == "0"
    assert r_101.headers.get("X-RateLimit-Reset") is not None
    print("  -> [✓] Общий Rate Limiter (100/15м) сработал точно на 101-м запросе!")

    # -------------------------------------------------------------------------
    # ЭТАП 5: СТРОГИЙ RATE LIMITING ДЛЯ /auth/login (5 ПОПЫТОК -> 6-Я = 429)
    # -------------------------------------------------------------------------
    sep("ЭТАП 5: СТРОГИЙ RATE LIMITING ДЛЯ /auth/login (5 ПОПЫТОК / 15 МИН)")

    requests.post(f"{GATEWAY_URL}/gateway/reset-limits")
    for attempt in range(1, 6):
        r = requests.post(f"{GATEWAY_URL}/auth/login", json={
            "email": user_email, "password": "wrong_password"
        })
        assert r.status_code == 401
        print(
            f"  Попытка входа #{attempt}: HTTP {r.status_code} | "
            f"X-RateLimit-Limit={r.headers.get('X-RateLimit-Limit')}, "
            f"X-RateLimit-Remaining={r.headers.get('X-RateLimit-Remaining')}"
        )

    r_6 = requests.post(f"{GATEWAY_URL}/auth/login", json={
        "email": user_email, "password": "userPass123"
    })
    print(
        f"  Попытка входа #6: HTTP {r_6.status_code} | "
        f"X-RateLimit-Limit={r_6.headers.get('X-RateLimit-Limit')}, "
        f"X-RateLimit-Remaining={r_6.headers.get('X-RateLimit-Remaining')}"
    )
    print(f"  Тело ответа 429: {r_6.json()}")
    assert r_6.status_code == 429
    assert r_6.headers.get("X-RateLimit-Limit") == "5"
    assert r_6.headers.get("X-RateLimit-Remaining") == "0"
    print("  -> [✓] Строгий Rate Limiter на /auth/login (5/15м) заблокировал 6-ю попытку!")

    # Возвращаем чистые лимиты после теста
    requests.post(f"{GATEWAY_URL}/gateway/reset-limits")

    print("\n" + "=" * 78)
    print("  ИТОГ: ВСЕ ТРЕБОВАНИЯ ЛАБОРАТОРНОЙ РАБОТЫ №7 ВЫПОЛНЕНЫ НА 100%! [OK]")
    print("=" * 78)

if __name__ == "__main__":
    main()
