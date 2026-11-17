import os
import sys
import time
import subprocess
from dotenv import load_dotenv

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(CURRENT_DIR, ".env"))

def main():
    print("=" * 75)
    print("  ЛОКАЛЬНЫЙ ЗАПУСК ЛАБОРАТОРНОЙ РАБОТЫ №7 (JWT + GATEWAY + RBAC + RL)")
    print("=" * 75)

    env = os.environ.copy()
    env["PYTHONPATH"] = CURRENT_DIR
    env.setdefault("JWT_SECRET", "tpu_lab7_jwt_secret_key_8i42_2026_secure")
    env.setdefault("JWT_ALGORITHM", "HS256")
    env.setdefault("JWT_EXPIRE_MINUTES", "60")
    env["AUTH_DB_PATH"] = os.path.join(CURRENT_DIR, "auth_users.db")
    env["AUTH_SERVICE_URL"] = "http://127.0.0.1:8001"
    env["CATALOG_SERVICE_URL"] = "http://127.0.0.1:8002"
    env["ORDER_SERVICE_URL"] = "http://127.0.0.1:8003"

    services = [
        ("Auth Service (8001)", "auth_service.app:app", "8001"),
        ("Catalog Service (8002)", "catalog_service.app:app", "8002"),
        ("Order Service (8003)", "order_service.app:app", "8003"),
        ("API Gateway (8000)", "api_gateway.app:app", "8000"),
    ]

    processes = []
    try:
        for idx, (name, target, port) in enumerate(services, 1):
            print(f"[{idx}/4] Запуск {name}...")
            proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", target, "--host", "127.0.0.1", "--port", port],
                env=env,
                cwd=CURRENT_DIR
            )
            processes.append((name, proc))
            time.sleep(0.7)

        print("\n" + "=" * 75)
        print("  ВСЕ 4 СЕРВИСА УСПЕШНО ЗАПУЩЕНЫ!")
        print("  -> API Gateway Dashboard: http://localhost:8000/")
        print("  -> Gateway Swagger UI:    http://localhost:8000/docs")
        print("  -> Auth Service:          http://localhost:8001/docs")
        print("  -> Catalog Service:       http://localhost:8002/docs")
        print("  -> Order Service:         http://localhost:8003/docs")
        print("  -> Запуск автотестов:     python test_security.py")
        print("=" * 75)
        print("\nНажмите Ctrl+C для плавной остановки сервисов...\n")

        while True:
            time.sleep(1)
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"Внимание: процесс {name} завершился с кодом {proc.returncode}")
                    return

    except KeyboardInterrupt:
        print("\nОстановка сервисов...")
    finally:
        for name, proc in processes:
            print(f"Останавливаю {name} (PID {proc.pid})...")
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        print("Все сервисы остановлены.")

if __name__ == "__main__":
    main()
