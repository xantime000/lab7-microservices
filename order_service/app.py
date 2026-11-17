import uuid
import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(
    title="Order Service (RBAC)",
    description="Внутренний сервис заказов. Проверяет роль пользователя (user или admin) по заголовкам X-User-Id и X-User-Role от API Gateway.",
    version="1.0.0"
)

orders_db: List[Dict[str, Any]] = []

ALLOWED_ROLES = {"user", "admin"}

class CreateOrderRequest(BaseModel):
    product_id: str = Field(..., example="prod-1")
    quantity: int = Field(1, ge=1, example=2)
    total_amount: float = Field(..., gt=0, example=145000.0)

def check_role(x_user_id: Optional[str], x_user_role: Optional[str]):
    """Проверка RBAC: заказ может создать любая авторизованная роль (user или admin)"""
    if not x_user_id or not x_user_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: отсутствуют заголовки X-User-Id / X-User-Role от API Gateway"
        )
    if x_user_role not in ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: недопустимая роль '{x_user_role}'"
        )

@app.get("/health")
def health():
    return {"status": "ok", "service": "order-service", "orders_count": len(orders_db)}

@app.post("/orders", status_code=status.HTTP_201_CREATED, summary="Создание заказа (доступно user и admin)")
def create_order(
    req: CreateOrderRequest,
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role")
):
    check_role(x_user_id, x_user_role)

    order = {
        "order_id": f"ord-{uuid.uuid4().hex[:8]}",
        "user_id": x_user_id,
        "user_role": x_user_role,
        "product_id": req.product_id,
        "quantity": req.quantity,
        "total_amount": req.total_amount,
        "status": "CREATED",
        "created_at": datetime.datetime.utcnow().isoformat() + "Z"
    }
    orders_db.append(order)
    return {
        "message": "Заказ успешно создан",
        "order": order
    }

@app.get("/orders", summary="Просмотр заказов (user — только свои, admin — все)")
def list_orders(
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role")
):
    check_role(x_user_id, x_user_role)

    if x_user_role == "admin":
        visible_orders = list(reversed(orders_db))
    else:
        visible_orders = [o for o in reversed(orders_db) if o["user_id"] == x_user_id]

    return {
        "requested_by": x_user_id,
        "role": x_user_role,
        "orders": visible_orders
    }
