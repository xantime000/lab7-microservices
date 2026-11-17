import uuid
import datetime
from typing import Dict, Any, Optional
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(
    title="Catalog Service (RBAC)",
    description="Внутренний сервис каталога товаров. Проверяет права доступа (RBAC) на основе заголовков X-User-Role от API Gateway.",
    version="1.0.0"
)

# Начальный каталог товаров (in-memory)
products_db: Dict[str, Dict[str, Any]] = {
    "prod-1": {
        "id": "prod-1",
        "name": "Ноутбук ThinkPad X1 Carbon",
        "price": 145000.0,
        "stock": 8,
        "created_by": "system",
        "created_at": "2026-11-17T10:00:00Z"
    },
    "prod-2": {
        "id": "prod-2",
        "name": "Механическая клавиатура Keychron K2",
        "price": 11500.0,
        "stock": 25,
        "created_by": "system",
        "created_at": "2026-11-17T10:05:00Z"
    },
    "prod-3": {
        "id": "prod-3",
        "name": "Монитор Dell UltraSharp 27",
        "price": 54000.0,
        "stock": 12,
        "created_by": "system",
        "created_at": "2026-11-17T10:10:00Z"
    }
}

class CreateProductRequest(BaseModel):
    name: str = Field(..., example="Беспроводная мышь Logitech MX Master 3S")
    price: float = Field(..., gt=0, example=9900.0)
    stock: int = Field(10, ge=0, example=15)

def require_authenticated(x_user_id: Optional[str], x_user_role: Optional[str]):
    """Проверка, что запрос прошел через API Gateway и содержит заголовки авторизации"""
    if not x_user_id or not x_user_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: отсутствуют заголовки X-User-Id / X-User-Role от API Gateway"
        )

def require_admin(x_user_id: Optional[str], x_user_role: Optional[str]):
    """Проверка RBAC: доступ разрешен ТОЛЬКО администратору (role == 'admin')"""
    require_authenticated(x_user_id, x_user_role)
    if x_user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: admin only (текущая роль: '{x_user_role}')"
        )

@app.get("/health")
def health():
    return {"status": "ok", "service": "catalog-service", "products_count": len(products_db)}

@app.get("/products", summary="Просмотр каталога товаров (доступно user и admin)")
def list_products(
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role")
):
    require_authenticated(x_user_id, x_user_role)
    return {
        "requested_by": x_user_id,
        "role": x_user_role,
        "items": list(products_db.values())
    }

@app.post("/products", status_code=status.HTTP_201_CREATED, summary="Создание товара (ТОЛЬКО admin)")
def create_product(
    req: CreateProductRequest,
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role")
):
    # RBAC проверка роли admin на основе заголовка X-User-Role от API Gateway
    require_admin(x_user_id, x_user_role)

    product_id = f"prod-{uuid.uuid4().hex[:6]}"
    product = {
        "id": product_id,
        "name": req.name,
        "price": req.price,
        "stock": req.stock,
        "created_by": x_user_id,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z"
    }
    products_db[product_id] = product
    return {
        "message": "Товар успешно создан администратором",
        "product": product
    }

@app.delete("/products/{product_id}", summary="Удаление товара (ТОЛЬКО admin)")
def delete_product(
    product_id: str,
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role")
):
    # RBAC проверка роли admin
    require_admin(x_user_id, x_user_role)

    if product_id not in products_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Товар '{product_id}' не найден")

    deleted = products_db.pop(product_id)
    return {
        "message": f"Товар '{product_id}' удален администратором {x_user_id}",
        "deleted": deleted
    }
