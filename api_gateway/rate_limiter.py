import os
import time
import threading
from typing import Dict, Tuple

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "900"))      # 15 минут
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "100"))          # 100 запросов / 15 мин
LOGIN_RATE_LIMIT_MAX_REQUESTS = int(os.getenv("LOGIN_RATE_LIMIT_MAX_REQUESTS", "5")) # 5 попыток / 15 мин

class RateLimiter:
    """
    Потокобезопасный ограничитель частоты запросов (Fixed Window Rate Limiter) по IP.
    Поддерживает раздельные квоты (общий лимит 100/15м и строгий лимит 5/15м для /auth/login).
    Всегда формирует стандартные заголовки:
      - X-RateLimit-Limit
      - X-RateLimit-Remaining
      - X-RateLimit-Reset
    """
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        # ip -> {"count": int, "reset_at": float}
        self._storage: Dict[str, Dict[str, float]] = {}

    def check(self, client_ip: str) -> Tuple[bool, Dict[str, str]]:
        now = time.time()
        with self._lock:
            entry = self._storage.get(client_ip)
            if not entry or now >= entry["reset_at"]:
                entry = {
                    "count": 0,
                    "reset_at": now + self.window_seconds
                }
                self._storage[client_ip] = entry

            reset_timestamp = int(entry["reset_at"])

            if entry["count"] >= self.max_requests:
                headers = {
                    "X-RateLimit-Limit": str(self.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_timestamp),
                    "Retry-After": str(max(1, reset_timestamp - int(now)))
                }
                return False, headers

            entry["count"] += 1
            remaining = max(0, self.max_requests - int(entry["count"]))
            headers = {
                "X-RateLimit-Limit": str(self.max_requests),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_timestamp)
            }
            return True, headers

    def reset_all(self):
        with self._lock:
            self._storage.clear()

# Общий лимитер для всех API-маршрутов (100 запросов за 15 минут)
general_limiter = RateLimiter(
    max_requests=RATE_LIMIT_MAX_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS
)

# Строгий лимитер для защиты /auth/login от перебора паролей (5 попыток за 15 минут)
login_limiter = RateLimiter(
    max_requests=LOGIN_RATE_LIMIT_MAX_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS
)
