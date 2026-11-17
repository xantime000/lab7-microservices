import os
import sys
import httpx
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api_gateway.rate_limiter import (
    general_limiter,
    login_limiter,
    RATE_LIMIT_MAX_REQUESTS,
    LOGIN_RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS
)

load_dotenv()

# Секретный ключ JWT загружается строго из переменной окружения
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("Переменная окружения JWT_SECRET не задана! Укажите ее в .env или docker-compose.yml")

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://127.0.0.1:8001")
CATALOG_SERVICE_URL = os.getenv("CATALOG_SERVICE_URL", "http://127.0.0.1:8002")
ORDER_SERVICE_URL = os.getenv("ORDER_SERVICE_URL", "http://127.0.0.1:8003")

app = FastAPI(
    title="API Gateway (JWT Validation + Rate Limiting + RBAC Proxy)",
    description="Единая точка входа в микросервисную архитектуру: валидация JWT, проброс X-User-Id / X-User-Role и Rate Limiting.",
    version="1.0.0"
)

# Маршруты, не требующие JWT-аутентификации
PUBLIC_PATHS = {"/", "/health", "/docs", "/openapi.json", "/redoc", "/gateway/reset-limits"}
PROTECTED_PREFIXES = ("/products", "/orders")

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    """
    Централизованный middleware API Gateway:
    1. Rate Limiting (5 req/15m для /auth/login, 100 req/15m для остальных API-маршрутов)
       с обязательными заголовками X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset.
    2. Валидация JWT (Authorization: Bearer <token>) для защищенных маршрутов (/products, /orders)
       и сохранение извлеченных claims (sub, role) в request.state.
    """
    path = request.url.path
    method = request.method.upper()
    rl_headers = {}

    # 1. Rate Limiting (применяем ко всем API-маршрутам)
    if path not in PUBLIC_PATHS:
        client_ip = get_client_ip(request)
        if path == "/auth/login" and method == "POST":
            allowed, rl_headers = login_limiter.check(client_ip)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Too Many Requests",
                        "detail": "Слишком много попыток входа. Попробуйте позже."
                    },
                    headers=rl_headers
                )
        else:
            allowed, rl_headers = general_limiter.check(client_ip)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Too Many Requests",
                        "detail": "Слишком много запросов, попробуйте позже."
                    },
                    headers=rl_headers
                )

    # 2. Валидация JWT для защищенных маршрутов
    if path.startswith(PROTECTED_PREFIXES):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "detail": "No token provided"},
                headers=rl_headers
            )

        token = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = decoded.get("sub")
            user_role = decoded.get("role")
            if not user_id or not user_role:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Unauthorized", "detail": "Invalid token payload (missing sub/role)"},
                    headers=rl_headers
                )
            request.state.user_id = str(user_id)
            request.state.user_role = str(user_role)
        except jwt.ExpiredSignatureError:
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "detail": "Token expired"},
                headers=rl_headers
            )
        except jwt.InvalidTokenError:
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "detail": "Invalid token"},
                headers=rl_headers
            )

    response = await call_next(request)

    # Добавляем обязательные заголовки X-RateLimit-* в ответ
    for k, v in rl_headers.items():
        response.headers[k] = v

    return response

async def proxy_request(request: Request, target_base_url: str, inject_user_headers: bool = False) -> Response:
    """Проксирование HTTP-запроса во внутренний микросервис с пробросом X-User-Id и X-User-Role"""
    target_url = f"{target_base_url}{request.url.path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Копируем безопасные заголовки, удаляя потенциально подделанные клиентом X-User-* и Authorization
    forward_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in ("host", "content-length", "authorization", "x-user-id", "x-user-role"):
            continue
        forward_headers[k] = v

    if inject_user_headers:
        forward_headers["X-User-Id"] = getattr(request.state, "user_id", "")
        forward_headers["X-User-Role"] = getattr(request.state, "user_role", "")

    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream_resp = await client.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                content=body
            )
    except httpx.RequestError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": "Bad Gateway", "detail": f"Внутренний сервис недоступен: {exc}"}
        )

    excluded_resp_headers = {"content-encoding", "transfer-encoding", "connection", "content-length"}
    resp_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in excluded_resp_headers
    }

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=upstream_resp.headers.get("content-type", "application/json")
    )

# =============================================================================
# ПРОКСИ-МАРШРУТЫ API GATEWAY
# =============================================================================

@app.api_route("/auth/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_auth(request: Request, path: str):
    return await proxy_request(request, AUTH_SERVICE_URL, inject_user_headers=False)

@app.api_route("/products", methods=["GET", "POST"])
async def proxy_products_root(request: Request):
    return await proxy_request(request, CATALOG_SERVICE_URL, inject_user_headers=True)

@app.api_route("/products/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_products(request: Request, path: str):
    return await proxy_request(request, CATALOG_SERVICE_URL, inject_user_headers=True)

@app.api_route("/orders", methods=["GET", "POST"])
async def proxy_orders_root(request: Request):
    return await proxy_request(request, ORDER_SERVICE_URL, inject_user_headers=True)

@app.api_route("/orders/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_orders(request: Request, path: str):
    return await proxy_request(request, ORDER_SERVICE_URL, inject_user_headers=True)

@app.post("/gateway/reset-limits", summary="Сброс счетчиков Rate Limiter (для демонстрации)")
def reset_limits():
    general_limiter.reset_all()
    login_limiter.reset_all()
    return {"message": "Счетчики Rate Limiter сброшены"}

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "api-gateway",
        "rate_limit": f"{RATE_LIMIT_MAX_REQUESTS} req / {RATE_LIMIT_WINDOW_SECONDS}s",
        "login_rate_limit": f"{LOGIN_RATE_LIMIT_MAX_REQUESTS} req / {RATE_LIMIT_WINDOW_SECONDS}s"
    }

# =============================================================================
# ИНТЕРАКТИВНЫЙ ВЕБ-ДАШБОРД БЕЗОПАСНОСТИ (http://localhost:8000/)
# =============================================================================

@app.get("/", response_class=HTMLResponse, summary="Веб-дашборд тестирования безопасности")
def dashboard():
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>API Gateway — Безопасность микросервисов (JWT + RBAC + Rate Limiting)</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; line-height: 1.5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .nav {{ display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }}
        .nav a {{ background: #21262d; border: 1px solid #30363d; padding: 8px 14px; border-radius: 6px; color: #58a6ff; text-decoration: none; font-size: 13px; font-weight: 500; }}
        .nav a:hover {{ background: #30363d; }}
        .nav a.active {{ background: #1f6feb; color: white; border-color: #58a6ff; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 18px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
        h1 {{ color: #58a6ff; margin: 0 0 8px 0; font-size: 22px; }}
        h2 {{ color: #c9d1d9; margin: 0 0 12px 0; font-size: 16px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }}
        input, select {{ background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 10px; border-radius: 6px; font-size: 13px; width: 100%; box-sizing: border-box; margin-bottom: 8px; }}
        .btn {{ cursor: pointer; padding: 8px 14px; border-radius: 6px; border: none; font-size: 13px; font-weight: 600; transition: 0.15s; margin-right: 6px; margin-bottom: 6px; }}
        .btn-primary {{ background: #1f6feb; color: white; }}
        .btn-success {{ background: #238636; color: white; }}
        .btn-danger {{ background: #da3633; color: white; }}
        .btn-warn {{ background: #9e6a03; color: white; }}
        .btn-sec {{ background: #30363d; color: #c9d1d9; }}
        pre {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 12px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 8px 0 0 0; color: #79c0ff; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 10px; font-size: 12px; font-weight: bold; }}
        .b-ok {{ background: #238636; color: white; }}
        .b-err {{ background: #da3633; color: white; }}
        .b-warn {{ background: #9e6a03; color: white; }}
    </style>
</head>
<body>
<div class="container">
    <div class="nav">
        <a href="/" class="active">API Gateway Dashboard (:8000)</a>
        <a href="/docs" target="_blank">Gateway Swagger</a>
        <a href="http://localhost:8001/docs" target="_blank">Auth Service (:8001)</a>
        <a href="http://localhost:8002/docs" target="_blank">Catalog Service (:8002)</a>
        <a href="http://localhost:8003/docs" target="_blank">Order Service (:8003)</a>
        <span style="margin-left: auto; color: #8b949e; font-size: 12px;">ТПУ • гр. 8И42 • Лабораторная №7</span>
    </div>

    <div class="card">
        <h1>Безопасность микросервисов: JWT + API Gateway + RBAC + Rate Limiting</h1>
        <p style="color:#8b949e; margin:0;">
            Поток запроса: <strong>Client</strong> &rarr; <strong>API Gateway</strong> (Rate Limit + JWT validation + X-User-Id/X-User-Role) &rarr; <strong>Internal Service</strong> (RBAC check).
            Лимиты: <strong>{RATE_LIMIT_MAX_REQUESTS} req / {RATE_LIMIT_WINDOW_SECONDS // 60} мин</strong> (общий), <strong>{LOGIN_RATE_LIMIT_MAX_REQUESTS} req / {RATE_LIMIT_WINDOW_SECONDS // 60} мин</strong> (/auth/login).
        </p>
    </div>

    <div class="grid">
        <div class="card">
            <h2>1. Регистрация и Логин (Auth Service)</h2>
            <input id="email" value="student@tpu.ru" placeholder="Email">
            <input id="password" type="password" value="secret123" placeholder="Пароль (хешируется bcrypt)">
            <select id="role">
                <option value="user">Роль: user (обычный пользователь)</option>
                <option value="admin">Роль: admin (администратор)</option>
            </select>
            <div>
                <button class="btn btn-primary" onclick="doRegister()">POST /auth/register</button>
                <button class="btn btn-success" onclick="doLogin()">POST /auth/login (получить JWT)</button>
                <button class="btn btn-sec" onclick="quickSetup('user')">Быстрый user</button>
                <button class="btn btn-sec" onclick="quickSetup('admin')">Быстрый admin</button>
            </div>
            <div style="margin-top:10px; font-size:12px; color:#8b949e;">Текущий JWT токен и декодированный Payload:</div>
            <pre id="jwtBox">Токен еще не получен</pre>
        </div>

        <div class="card">
            <h2>2. Проверка RBAC, 401 и Rate Limiting</h2>
            <div>
                <button class="btn btn-sec" onclick="callApi('GET', '/products')">GET /products (user/admin)</button>
                <button class="btn btn-primary" onclick="callApi('POST', '/products', {{name:'Клавиатура Pro', price:12000, stock:5}})">POST /products (только admin)</button>
                <button class="btn btn-success" onclick="callApi('POST', '/orders', {{product_id:'prod-1', quantity:1, total_amount:145000}})">POST /orders (user/admin)</button>
                <button class="btn btn-sec" onclick="callApi('GET', '/orders')">GET /orders</button>
            </div>
            <div style="margin-top:8px;">
                <button class="btn btn-danger" onclick="callBadToken()">Запрос с поддельным JWT (401)</button>
                <button class="btn btn-warn" onclick="spamRateLimit()">Тест Rate Limit: 101 запрос (429)</button>
                <button class="btn btn-sec" onclick="resetLimits()">Сбросить лимиты</button>
            </div>
            <div style="margin-top:10px; font-size:12px; color:#8b949e;">Последний ответ и заголовки X-RateLimit-*:</div>
            <pre id="respBox">Нажмите любую кнопку для проверки</pre>
        </div>
    </div>
</div>

<script>
let currentToken = "";

function parseJwt(token) {{
    try {{
        const payload = token.split('.')[1];
        const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
        return JSON.parse(decodeURIComponent(escape(json)));
    }} catch (e) {{
        return null;
    }}
}}

function showResponse(status, headers, body) {{
    const rl = {{
        "X-RateLimit-Limit": headers.get("X-RateLimit-Limit"),
        "X-RateLimit-Remaining": headers.get("X-RateLimit-Remaining"),
        "X-RateLimit-Reset": headers.get("X-RateLimit-Reset")
    }};
    document.getElementById("respBox").textContent =
        `HTTP ${{status}}\\nRateLimit Headers: ${{JSON.stringify(rl, null, 2)}}\\nBody:\\n${{JSON.stringify(body, null, 2)}}`;
}}

async function doRegister() {{
    const res = await fetch('/auth/register', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{
            email: document.getElementById('email').value,
            password: document.getElementById('password').value,
            role: document.getElementById('role').value
        }})
    }});
    const data = await res.json();
    showResponse(res.status, res.headers, data);
}}

async function doLogin() {{
    const res = await fetch('/auth/login', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{
            email: document.getElementById('email').value,
            password: document.getElementById('password').value
        }})
    }});
    const data = await res.json();
    showResponse(res.status, res.headers, data);
    if (res.ok && data.access_token) {{
        currentToken = data.access_token;
        const decoded = parseJwt(currentToken);
        document.getElementById('jwtBox').textContent =
            `JWT:\\n${{currentToken}}\\n\\nDecoded Payload (claims):\\n${{JSON.stringify(decoded, null, 2)}}`;
    }}
}}

async function quickSetup(role) {{
    const email = role + '_' + Math.floor(Math.random()*1000) + '@tpu.ru';
    document.getElementById('email').value = email;
    document.getElementById('password').value = 'pass1234';
    document.getElementById('role').value = role;
    await doRegister();
    await doLogin();
}}

async function callApi(method, url, bodyObj=null) {{
    const headers = {{'Content-Type': 'application/json'}};
    if (currentToken) headers['Authorization'] = 'Bearer ' + currentToken;
    const opts = {{ method, headers }};
    if (bodyObj) opts.body = JSON.stringify(bodyObj);
    const res = await fetch(url, opts);
    const data = await res.json();
    showResponse(res.status, res.headers, data);
}}

async function callBadToken() {{
    const res = await fetch('/products', {{
        headers: {{'Authorization': 'Bearer invalid.forged.token123'}}
    }});
    const data = await res.json();
    showResponse(res.status, res.headers, data);
}}

async function spamRateLimit() {{
    if (!currentToken) {{
        alert('Сначала залогиньтесь (нажмите "Быстрый user" или "Быстрый admin")');
        return;
    }}
    document.getElementById('respBox').textContent = 'Отправка 101 запроса к GET /products...';
    let lastRes = null, lastData = null, count429 = 0;
    for (let i = 1; i <= 105; i++) {{
        const res = await fetch('/products', {{ headers: {{'Authorization': 'Bearer ' + currentToken}} }});
        lastRes = res;
        lastData = await res.json();
        if (res.status === 429) {{
            count429 = i;
            break;
        }}
    }}
    showResponse(lastRes.status, lastRes.headers, {{ triggered_on_request: count429, response: lastData }});
}}

async function resetLimits() {{
    const res = await fetch('/gateway/reset-limits', {{ method: 'POST' }});
    const data = await res.json();
    document.getElementById('respBox').textContent = JSON.stringify(data, null, 2);
}}
</script>
</body>
</html>
"""
