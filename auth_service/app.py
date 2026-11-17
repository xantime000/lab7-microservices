import os
import uuid
import sqlite3
import datetime
import threading
from typing import Literal, Optional
import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

load_dotenv()

# Секретный ключ загружается строго из переменной окружения (без хардкода в коде)
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("Переменная окружения JWT_SECRET не задана! Укажите ее в .env или docker-compose.yml")

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
AUTH_DB_PATH = os.getenv("AUTH_DB_PATH", "auth_users.db")

app = FastAPI(
    title="Auth Service (JWT + bcrypt)",
    description="Микросервис регистрации и аутентификации пользователей с выдачей JWT-токенов",
    version="1.0.0"
)

class UserRepository:
    """Хранилище пользователей в SQLite (пароли хранятся исключительно в виде bcrypt-хешей)"""
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    def create_user(self, email: str, password_hash: str, role: str) -> dict:
        user_id = f"user-{uuid.uuid4().hex[:8]}"
        created_at = datetime.datetime.utcnow().isoformat() + "Z"
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, email.lower().strip(), password_hash, role, created_at)
                )
                conn.commit()
                return {
                    "id": user_id,
                    "email": email.lower().strip(),
                    "role": role,
                    "created_at": created_at
                }
            except sqlite3.IntegrityError:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Пользователь с email '{email}' уже зарегистрирован"
                )
            finally:
                conn.close()

    def get_by_email(self, email: str) -> Optional[dict]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT id, email, password_hash, role, created_at FROM users WHERE email = ?",
                    (email.lower().strip(),)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def list_users(self) -> list:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT id, email, password_hash, role, created_at FROM users ORDER BY created_at DESC"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

user_repo = UserRepository(AUTH_DB_PATH)

def hash_password(plain_password: str) -> str:
    """Хеширование пароля с генерацией криптографической соли через bcrypt"""
    salt = bcrypt.gensalt(rounds=10)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, password_hash: str) -> bool:
    """Безопасная проверка пароля против bcrypt-хеша"""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False

def generate_jwt(user_id: str, email: str, role: str) -> str:
    """Генерация JWT-токена с обязательными claims: sub, role, exp"""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES)).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

class RegisterRequest(BaseModel):
    email: str = Field(..., example="alex@tpu.ru")
    password: str = Field(..., min_length=4, example="strongPass123")
    role: Literal["user", "admin"] = Field("user", description="Роль пользователя: user или admin")

class LoginRequest(BaseModel):
    email: str = Field(..., example="alex@tpu.ru")
    password: str = Field(..., example="strongPass123")

@app.get("/health")
def health():
    return {"status": "ok", "service": "auth-service"}

@app.post("/auth/register", status_code=status.HTTP_201_CREATED, summary="Регистрация пользователя (bcrypt)")
def register(req: RegisterRequest):
    password_hash = hash_password(req.password)
    user = user_repo.create_user(req.email, password_hash, req.role)
    return {
        "message": "Пользователь успешно зарегистрирован",
        "user": user
    }

@app.post("/auth/login", summary="Аутентификация и выдача JWT")
def login(req: LoginRequest):
    user = user_repo.get_by_email(req.email)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль"
        )

    token = generate_jwt(user_id=user["id"], email=user["email"], role=user["role"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRE_MINUTES * 60,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "role": user["role"]
        }
    }

@app.get("/auth/users", summary="Список пользователей (для проверки хеширования bcrypt)")
def list_users():
    return user_repo.list_users()
