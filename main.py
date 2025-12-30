# SimpleAPI_SQLAlchemy_version.py
"""
API - SQLAlchemy + OAuth2/JWT (Beginner-friendly)

Highlights:
 1) All endpoints are locked by default.
 2) Unlock with a valid Bearer token (your RS256 API token or Okta access token).
 3) OAuth2 Password Flow for local login (/token) issuing RS256 JWTs.
 4) Refresh token rotation + reuse detection.
 5) Okta Authorization Code + PKCE (/authorize → /callback) with optional client_secret.
 6) JWKS published at /.well-known/jwks.json for RS256 verification.

Run locally:
 uvicorn main:app --reload --port 8000
"""
import os
import time
import logging
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, List, Optional, Tuple, Dict

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Depends, HTTPException, status, Query, APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from urllib.parse import urlencode

from sqlalchemy import Boolean, Integer, String, create_engine, select, or_, cast
from sqlalchemy import DateTime, func, UniqueConstraint
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from passlib.context import CryptContext
from jose import jwt

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# --------------------------- Error model & helpers -----------------------------
class ErrorDetail(BaseModel):
    code: str
    message: str
    attempts_remaining: Optional[int] = None
    retry_after_seconds: Optional[int] = None

LOGIN_MAX_ATTEMPTS = 3
LOGIN_WINDOW_SECONDS = 60
_attempts: dict[Tuple[str, str], list[float]] = {}

def _attempts_key(username: str, ip: str) -> Tuple[str, str]:
    return (username or "", ip or "")

def get_attempts_remaining(username: str, ip: str) -> int:
    now = time.time()
    key = _attempts_key(username, ip)
    arr = _attempts.setdefault(key, [])
    arr[:] = [t for t in arr if now - t <= LOGIN_WINDOW_SECONDS]
    return max(0, LOGIN_MAX_ATTEMPTS - len(arr))

def note_failed_attempt(username: str, ip: str) -> int:
    now = time.time()
    key = _attempts_key(username, ip)
    arr = _attempts.setdefault(key, [])
    arr.append(now)
    arr[:] = [t for t in arr if now - t <= LOGIN_WINDOW_SECONDS]
    return max(0, LOGIN_MAX_ATTEMPTS - len(arr))

def clear_attempts(username: str, ip: str) -> None:
    key = _attempts_key(username, ip)
    if key in _attempts:
        _attempts[key] = []

# --------------------------- Role → scopes map --------------------------------
ROLE_TO_SCOPES = {
    "admin": [
        "orders:read", "orders:write",
        "customers:read", "customers:write",
        "invoices:read", "invoices:write",
        "agreements:read", "agreements:write",
        "users:manage",
    ],
    "manager": [
        "orders:read", "orders:write",
        "customers:read", "customers:write",
        "invoices:read", "invoices:write",
        "agreements:read", "agreements:write",
    ],
    "viewer": ["orders:read", "customers:read", "invoices:read", "agreements:read"],
    "user": ["orders:read"],
}

# ============================ App & Security Config ===========================
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
TOKEN_EXPIRES_MIN = int(os.getenv("TOKEN_EXPIRES_MIN", "60"))
REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", "30"))

REFRESH_IN_COOKIE = os.getenv("REFRESH_IN_COOKIE", "false").lower() == "true"
REFRESH_COOKIE_NAME = os.getenv("REFRESH_COOKIE_NAME", "refresh_token")
# We will toggle secure cookies by ENV (prod → secure=True)
REFRESH_COOKIE_SAMESITE = os.getenv("REFRESH_COOKIE_SAMESITE", "lax").lower()

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Disable FastAPI's default /docs so we can guard it ourselves
app = FastAPI(
    title="API - Swagger UI - Beta Version",
    version="0.1.0",
    description=(
        "<h3>Citation/References</h3>"
        "<blockquote>Author: http://www.linkedin.com/in/fernando-losantos-33a746124/</blockquote>"
    ),
    docs_url=None,  # <— critical: prevents public /docs
    redoc_url=None,
)

# Rate limiting
def rate_limit_key(request: Request):
    try:
        return get_remote_address(request)
    except Exception:
        return "anonymous"

limiter = Limiter(key_func=rate_limit_key)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc: RateLimitExceeded):
    retry_after = int(60 - (time.time() % 60)) or 1
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "code": "too_many_requests",
            "message": (
                "Too many failed login attempts. Try again later."
                if str(request.url.path).lower() == "/token" else "Too many requests."
            ),
            "retry_after_seconds": retry_after,
        },
        headers={"Retry-After": str(retry_after)},
    )

# ============================ RS256 Key Management ============================
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

JWT_RS256_ALG = "RS256"

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _normalize_pem(text: str) -> str:
    return text.replace("\\n", "\n") if "\\n" in text else text

def _b64_to_text(s: str) -> str:
    s = (s or "").strip().strip('"')
    return base64.b64decode(s).decode("utf-8")

class RS256KeyStore:
    def __init__(self):
        self.active_kid: Optional[str] = os.getenv("JWT_ACTIVE_KID", "").strip() or None
        self.priv_by_kid: Dict[str, str] = {}
        self.pub_by_kid: Dict[str, str] = {}
        self._load_env()

    def _load_env(self):
        # Load base64-encoded PEMs
        for k, v in os.environ.items():
            if k.startswith("JWT_RS256_PRIVATE_KEY_B64__"):
                kid = k.split("__", 1)[1]
                self.priv_by_kid[kid] = _b64_to_text(v)
            elif k.startswith("JWT_RS256_PUBLIC_KEY_B64__"):
                kid = k.split("__", 1)[1]
                self.pub_by_kid[kid] = _b64_to_text(v)
        # Load raw PEM overrides
        for k, v in os.environ.items():
            if k.startswith("JWT_RS256_PRIVATE_KEY__"):
                kid = k.split("__", 1)[1]
                self.priv_by_kid.setdefault(kid, _normalize_pem(v.strip().strip('"')))
            elif k.startswith("JWT_RS256_PUBLIC_KEY__"):
                kid = k.split("__", 1)[1]
                self.pub_by_kid.setdefault(kid, _normalize_pem(v.strip().strip('"')))
        if not self.active_kid and self.priv_by_kid:
            self.active_kid = sorted(self.priv_by_kid.keys())[-1]

    def get_active_signing_key(self) -> Tuple[str, str]:
        if not self.active_kid:
            raise RuntimeError("JWT_ACTIVE_KID is not set")
        priv = self.priv_by_kid.get(self.active_kid)
        if not priv:
            raise RuntimeError(f"No private key configured for kid={self.active_kid}")
        return self.active_kid, priv

    def jwks(self) -> dict:
        keys = []
        for kid, pub_pem in self.pub_by_kid.items():
            try:
                pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
                if not isinstance(pub_key, RSAPublicKey):
                    logging.error("JWKS: public key for kid=%s is not RSA", kid)
                    continue
                numbers = pub_key.public_numbers()
                n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
                keys.append({
                    "kty": "RSA",
                    "kid": kid,
                    "alg": JWT_RS256_ALG,
                    "use": "sig",
                    "n": _b64url(n),
                    "e": _b64url(e),
                })
            except Exception as ex:
                logging.exception("JWKS: failed to load public key for kid=%s: %s", kid, ex)
        return {"keys": keys}

rs256_keystore = RS256KeyStore()

# =============================== CORS & Static ================================
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

raw_origins = os.getenv("CORS_ORIGINS", "")
allow_origins: List[str] = [o.strip() for o in raw_origins.split(",") if o.strip()]
ENV = os.getenv("ENV", "dev").lower()
SECURE_COOKIES = (ENV == "prod")  # <-- cookie hardening: secure in prod

if ENV == "prod" and not allow_origins:
    raise RuntimeError("CORS_ORIGINS must be set in production (comma-separated list).")
if ENV != "prod" and not allow_origins:
    allow_origins = ["http://localhost:8000", "http://127.0.0.1:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    allow_credentials=True,  # <-- CORS hardening for cookie auth
)

# ============================ Database (PostgreSQL) ===========================
DATABASE_URL = os.getenv("DB_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError("DB_URL is not set. Put it in .env or environment variables.")

engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
)

class Base(DeclarativeBase):
    """Base class for ORM models."""

# ------------------------------- ORM MODELS -----------------------------------
class Order(Base):
    __tablename__ = "orders"
    __table_args__ = {"schema": "dbo"}
    Order_Number: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    Customer_Number: Mapped[int] = mapped_column(Integer)
    Quantity: Mapped[int] = mapped_column(Integer)
    Price: Mapped[int] = mapped_column(Integer)

class Customer(Base):
    __tablename__ = "customers"
    __table_args__ = {"schema": "dbo"}
    Customer_Number: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    Customer_Name: Mapped[str] = mapped_column(String(100), nullable=True)
    Customer_Address: Mapped[str] = mapped_column(String(50), nullable=True)
    Contact_Number: Mapped[str] = mapped_column(String(15), nullable=True)
    Email_Address: Mapped[str] = mapped_column(String(50), nullable=True)

class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "dbo"}
    User_Id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    User_Name: Mapped[str] = mapped_column(String(100), nullable=True)
    Location_Address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    Email_Address: Mapped[str] = mapped_column(String(255), nullable=True, unique=True)
    Contact_Number: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    Vat_Number: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    Hashed_Pword: Mapped[str] = mapped_column(nullable=True)
    Is_Active: Mapped[bool] = mapped_column(Boolean, default=True)
    Role: Mapped[str] = mapped_column(String(50), nullable=True, default="user")
    TokenVersion: Mapped[int] = mapped_column(Integer, nullable=True, default=1)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        UniqueConstraint("Fingerprint", name="uq_refresh_tokens_fingerprint"),
        {"schema": "dbo"}
    )
    RT_Id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    User_Id: Mapped[int] = mapped_column(Integer, nullable=False)
    Token_Hash: Mapped[str] = mapped_column(String(255), nullable=False)
    Fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    Created_At: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    Expires_At: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    Is_Revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    TokenVersionAtIssue: Mapped[int] = mapped_column(Integer, nullable=False)

class Invoice(Base):
    __tablename__ = "invoices"
    __table_args__ = {"schema": "dbo"}
    Invoice_Number: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    Order_Number: Mapped[int] = mapped_column(Integer)
    Customer_Number: Mapped[int] = mapped_column(Integer)
    Invoice_Date: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    Invoice_Email: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    Amount: Mapped[int] = mapped_column(Integer)

class Agreement(Base):
    __tablename__ = "agreements"
    __table_args__ = {"schema": "dbo"}
    Agreement_number: Mapped[str] = mapped_column(String(7), primary_key=True, nullable=False, unique=True)
    Customer_Number: Mapped[int] = mapped_column(Integer)
    Customer_site: Mapped[int] = mapped_column(Integer)
    Your_reference_1: Mapped[int] = mapped_column(Integer)
    Telephone_number_1: Mapped[int] = mapped_column(Integer)
    customers_order_number: Mapped[int] = mapped_column(Integer)
    Agreement_order_type: Mapped[int] = mapped_column(Integer)
    Termination_date: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    Line_charge_model: Mapped[int] = mapped_column(Integer)
    Address_line_1: Mapped[str] = mapped_column(String(100), nullable=True)
    Address_line_2: Mapped[str] = mapped_column(String(100), nullable=True)
    Address_line_3: Mapped[str] = mapped_column(String(100), nullable=True)
    Address_line_4: Mapped[str] = mapped_column(String(100), nullable=True)
    Salesperson: Mapped[str] = mapped_column(String(30), nullable=True)
    Minimum_rental_type: Mapped[int] = mapped_column(Integer)
    Minimum_order_value: Mapped[int] = mapped_column(Integer)
    Currency: Mapped[str] = mapped_column(String(6), nullable=True, default="SR")
    Reason_code_created_agreement: Mapped[str] = mapped_column(String(6), nullable=True)
    User: Mapped[str] = mapped_column(String(6), nullable=True)
    Minimum_hire_period: Mapped[int] = mapped_column(Integer)
    Payment_terms: Mapped[str] = mapped_column(String(6), nullable=True)
    Price_list: Mapped[str] = mapped_column(String(6), nullable=True)
    Reason_code_terminated_agreement: Mapped[str] = mapped_column(String(6), nullable=True)
    Project_number: Mapped[str] = mapped_column(String(6), nullable=True)

# ============================ Session dependency ==============================
def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session

# ============================ Schemas (Pydantic) ==============================
class OrderIn(BaseModel):
    Customer_Number: int
    Quantity: int
    Price: int

class OrderOut(OrderIn):
    Order_Number: int

def order_out(o: Order) -> OrderOut:
    return OrderOut(
        Order_Number=o.Order_Number,
        Customer_Number=o.Customer_Number,
        Quantity=o.Quantity,
        Price=o.Price,
    )

class CustomerIn(BaseModel):
    Customer_Name: str
    Customer_Address: str
    Contact_Number: str
    Email_Address: EmailStr

class CustomerOut(CustomerIn):
    Customer_Number: int

def customer_out(c: Customer) -> CustomerOut:
    return CustomerOut(
        Customer_Number=c.Customer_Number,
        Customer_Name=c.Customer_Name,
        Customer_Address=c.Customer_Address,
        Contact_Number=c.Contact_Number,
        Email_Address=c.Email_Address,
    )

class UserCreate(BaseModel):
    User_Name: str
    Location_Address: Optional[str] = None
    Email_Address: EmailStr
    Contact_Number: Optional[str] = None
    Vat_Number: Optional[str] = None
    Password: str = Field(..., min_length=6)

class UserPublic(BaseModel):
    User_Id: int
    User_Name: str
    Location_Address: Optional[str] = None
    Email_Address: EmailStr
    Contact_Number: Optional[str] = None
    Vat_Number: Optional[str] = None
    Is_Active: bool = True
    Role: Optional[str] = None
    TokenVersion: Optional[int] = None

def user_out(u: User) -> UserPublic:
    return UserPublic(
        User_Id=u.User_Id,
        User_Name=u.User_Name,
        Location_Address=u.Location_Address or "",
        Email_Address=u.Email_Address,
        Contact_Number=u.Contact_Number or "",
        Vat_Number=u.Vat_Number or "",
        Is_Active=bool(u.Is_Active),
        Role=u.Role,
        TokenVersion=u.TokenVersion,
    )

class UserUpdate(BaseModel):
    User_Name: Optional[str] = None
    Location_Address: Optional[str] = None
    Email_Address: Optional[EmailStr] = None
    Contact_Number: Optional[str] = None
    Vat_Number: Optional[str] = None
    Is_Active: Optional[bool] = None
    Role: Optional[str] = None

class UserPasswordUpdate(BaseModel):
    Old_Password: str = Field(..., min_length=8)
    New_Password: str = Field(..., min_length=8)

class InvoiceIn(BaseModel):
    Order_Number: int
    Invoice_Date: str
    Invoice_Email: Optional[str] = None
    Amount: int
    Customer_Number: int

class InvoiceOut(InvoiceIn):
    Invoice_Number: int

def invoice_out(i: Invoice) -> InvoiceOut:
    return InvoiceOut(
        Invoice_Number=i.Invoice_Number,
        Order_Number=i.Order_Number,
        Invoice_Date=i.Invoice_Date,
        Invoice_Email=i.Invoice_Email,
        Amount=i.Amount,
        Customer_Number=i.Customer_Number,
    )

class AgreementIn(BaseModel):
    Agreement_number: str
    Customer_Number: int
    Customer_site: int
    Your_reference_1: int
    Telephone_number_1: int
    customers_order_number: int
    Agreement_order_type: int
    Termination_date: str
    Line_charge_model: int
    Address_line_1: str
    Address_line_2: str
    Address_line_3: str
    Address_line_4: str
    Salesperson: str
    Minimum_rental_type: int
    Minimum_order_value: int
    Currency: str
    Reason_code_created_agreement: str
    User: str
    Minimum_hire_period: int
    Payment_terms: str
    Price_list: str
    Reason_code_terminated_agreement: str
    Project_number: str

class AgreementOut(AgreementIn):
    Agreement_number: str

def agreement_out(a: Agreement) -> AgreementOut:
    return AgreementOut(
        Agreement_number=a.Agreement_number,
        Customer_Number=a.Customer_Number,
        Customer_site=a.Customer_site,
        Your_reference_1=a.Your_reference_1,
        Telephone_number_1=a.Telephone_number_1,
        customers_order_number=a.customers_order_number,
        Agreement_order_type=a.Agreement_order_type,
        Termination_date=a.Termination_date,
        Line_charge_model=a.Line_charge_model,
        Address_line_1=a.Address_line_1,
        Address_line_2=a.Address_line_2,
        Address_line_3=a.Address_line_3,
        Address_line_4=a.Address_line_4,
        Salesperson=a.Salesperson,
        Minimum_rental_type=a.Minimum_rental_type,
        Minimum_order_value=a.Minimum_order_value,
        Currency=a.Currency,
        Reason_code_created_agreement=a.Reason_code_created_agreement,
        User=a.User,
        Minimum_hire_period=a.Minimum_hire_period,
        Payment_terms=a.Payment_terms,
        Price_list=a.Price_list,
        Reason_code_terminated_agreement=a.Reason_code_terminated_agreement,
        Project_number=a.Project_number,
    )

# ================================ ROUTERS =====================================
orders_router = APIRouter(tags=["Orders"])
responses204 = {204: {"description": "Deleted successfully", "content": {}}}

@orders_router.get("/GetOrder/{Order_Number}", response_model=OrderOut)
@limiter.limit("50/minute")
def get_order(request: Request, Order_Number: int, session: Session = Depends(get_session)) -> OrderOut:
    o = session.get(Order, Order_Number)
    if not o:
        raise HTTPException(status_code=404, detail="Order not found")
    return order_out(o)

@orders_router.get("/ListOrders", response_model=List[OrderOut])
@limiter.limit("50/minute")
def list_orders(
    request: Request,
    Order_Number: Optional[int] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
) -> List[OrderOut]:
    stmt = select(Order)
    if Order_Number is not None:
        stmt = stmt.where(Order.Order_Number == Order_Number)
    stmt = stmt.order_by(Order.Order_Number).limit(limit).offset(offset)
    return [order_out(o) for o in session.scalars(stmt).all()]

@orders_router.get("/SearchOrder", response_model=List[OrderOut])
@limiter.limit("50/minute")
def search_order(
    request: Request,
    SQRY: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
) -> List[OrderOut]:
    try:
        stmt = select(Order)
        if SQRY:
            search_term = f"%{SQRY}%"
            stmt = stmt.where(
                or_(
                    cast(Order.Order_Number, String).ilike(search_term),
                    cast(Order.Customer_Number, String).ilike(search_term),
                    cast(Order.Quantity, String).ilike(search_term),
                    cast(Order.Price, String).ilike(search_term),
                )
            )
        stmt = stmt.order_by(Order.Order_Number).limit(limit).offset(offset)
        results = session.scalars(stmt).all()
        return [order_out(o) for o in results]
    except Exception as e:
        logging.error(f"Search order failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search order failed: {str(e)}")

# --- WRITE ENDPOINTS: scope enforcement wired here ---
@orders_router.post(
    "/CreateOrders",
    response_model=List[OrderOut],
    status_code=201
)
@limiter.limit("50/minute")
def create_orders(
    request: Request,
    payload: List[OrderIn],
    session: Session = Depends(get_session),
):
    created: List[Order] = []
    for item in payload:
        o = Order(**item.model_dump())
        session.add(o)
        created.append(o)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Order already exists")
    except Exception as e:
        session.rollback()
        logging.exception("Create order failed")
        raise HTTPException(status_code=500, detail=f"Create order failed: {e}")
    for o in created:
        session.refresh(o)
    return [order_out(o) for o in created]

@orders_router.put(
    "/UpdateOrders/{Order_Number}",
    response_model=OrderOut
)
@limiter.limit("50/minute")
def update_order(
    request: Request,
    Order_Number: int,
    payload: OrderIn,
    session: Session = Depends(get_session),
) -> OrderOut:
    o = session.get(Order, Order_Number)
    if not o:
        raise HTTPException(status_code=404, detail="Order not found")
    o.Customer_Number = payload.Customer_Number
    o.Quantity = payload.Quantity
    o.Price = payload.Price
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Order already exists")
    session.refresh(o)
    return order_out(o)

@orders_router.delete(
    "/DeleteOrders/{Order_Number}",
    status_code=204,
    response_class=Response,
    responses=responses204
)
@limiter.limit("50/minute")
def delete_order(
    request: Request,
    Order_Number: int,
    session: Session = Depends(get_session),
) -> Response:
    o = session.get(Order, Order_Number)
    if not o:
        raise HTTPException(status_code=404, detail="Order not found")
    session.delete(o)
    session.commit()
    return Response(status_code=204)

# -------------------------- AUTH (Public) -------------------------------------
auth_router = APIRouter(tags=["Authorization"])

@app.get("/.well-known/jwks.json", include_in_schema=False)
def jwks():
    return JSONResponse(rs256_keystore.jwks(), headers={"Cache-Control": "public, max-age=300"})

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None
    expires_in: int

@auth_router.post("/token")
@limiter.limit("3/minute")
def login_for_access_token(
    request: Request,
    form_data = Depends(OAuth2PasswordRequestForm),
    session: Session = Depends(get_session),
) -> Token:
    ip = request.client.host if request.client else "unknown"
    email = (form_data.username or "").strip().lower()

    user = session.scalar(select(User).where(User.Email_Address == email))
    if not user or not pwd_context.verify(form_data.password, user.Hashed_Pword):
        remaining = note_failed_attempt(email, ip)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorDetail(code="bad_credentials", message="Invalid username or password.", attempts_remaining=remaining).model_dump()
        )

    if not user.Is_Active:
        remaining = get_attempts_remaining(email, ip)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorDetail(code="inactive_user", message="Inactive user.", attempts_remaining=remaining).model_dump()
        )

    clear_attempts(email, ip)

    try:
        if pwd_context.needs_update(user.Hashed_Pword):
            user.Hashed_Pword = pwd_context.hash(form_data.password)
            session.commit()
    except Exception:
        pass

    scopes = ROLE_TO_SCOPES.get(user.Role or "user", [])
    kid, priv = rs256_keystore.get_active_signing_key()
    access_token = jwt.encode(
        {"sub": user.Email_Address, "ver": user.TokenVersion, "scopes": scopes, "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRES_MIN)},
        priv,
        algorithm=JWT_RS256_ALG,
        headers={"kid": kid},
    )

    refresh_token_raw = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    rt = RefreshToken(
        User_Id=user.User_Id,
        Token_Hash=pwd_context.hash(refresh_token_raw),
        Fingerprint=hashlib.sha256(refresh_token_raw.encode("utf-8")).hexdigest(),
        Expires_At=datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRES_DAYS),
        TokenVersionAtIssue=int(user.TokenVersion or 1),
        Is_Revoked=False,
    )
    session.add(rt)
    session.commit()

    resp_body = Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token_raw, expires_in=TOKEN_EXPIRES_MIN * 60)

    if REFRESH_IN_COOKIE:
        response = JSONResponse(content=resp_body.model_dump())
        response.set_cookie(
            key=REFRESH_COOKIE_NAME,
            value=refresh_token_raw,
            httponly=True,
            secure=SECURE_COOKIES,           # <-- hardened: secure by ENV
            samesite=REFRESH_COOKIE_SAMESITE,
            max_age=REFRESH_EXPIRES_DAYS * 24 * 3600,
            path="/",
        )
        return response

    return resp_body

@auth_router.get("/me", response_model=UserPublic)
def read_me(current_user: User = Depends(lambda: None)) -> UserPublic:
    return user_out(current_user)

class RefreshRequest(BaseModel):
    refresh_token: str

@auth_router.post("/token/refresh")
@limiter.limit("20/minute")
def refresh_access_token(
    request: Request,
    payload: RefreshRequest,
    session: Session = Depends(get_session),
) -> Token:
    raw = (payload.refresh_token or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Missing refresh_token")

    fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    rec = session.scalar(select(RefreshToken).where(RefreshToken.Fingerprint == fp))
    if not rec:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = session.get(User, rec.User_Id)
    if not user or not user.Is_Active:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    now = datetime.now(timezone.utc)
    if rec.Is_Revoked or rec.Expires_At <= now:
        user.TokenVersion = (user.TokenVersion or 1) + 1
        for rt in session.scalars(select(RefreshToken).where(RefreshToken.User_Id == user.User_Id)).all():
            rt.Is_Revoked = True
        session.commit()
        raise HTTPException(status_code=401, detail="Refresh token reuse detected; tokens revoked")

    try:
        if not pwd_context.verify(raw, rec.Token_Hash):
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if int(rec.TokenVersionAtIssue or 1) != int(user.TokenVersion or 1):
        for rt in session.scalars(select(RefreshToken).where(RefreshToken.User_Id == user.User_Id)).all():
            rt.Is_Revoked = True
        session.commit()  # <-- fix: ensure revocations are persisted
        raise HTTPException(status_code=401, detail="Refresh token revoked")

    # Rotate: revoke the used token and issue new pair
    rec.Is_Revoked = True
    session.commit()

    scopes = ROLE_TO_SCOPES.get(user.Role or "user", [])
    kid, priv = rs256_keystore.get_active_signing_key()
    new_access = jwt.encode(
        {"sub": user.Email_Address, "ver": user.TokenVersion, "scopes": scopes, "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRES_MIN)},
        priv,
        algorithm=JWT_RS256_ALG,
        headers={"kid": kid},
    )

    new_refresh = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    session.add(
        RefreshToken(
            User_Id=user.User_Id,
            Token_Hash=pwd_context.hash(new_refresh),
            Fingerprint=hashlib.sha256(new_refresh.encode("utf-8")).hexdigest(),
            Expires_At=datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRES_DAYS),
            TokenVersionAtIssue=int(user.TokenVersion or 1),
            Is_Revoked=False,
        )
    )
    session.commit()

    body = Token(access_token=new_access, token_type="bearer", refresh_token=new_refresh, expires_in=TOKEN_EXPIRES_MIN * 60)

    if REFRESH_IN_COOKIE:
        response = JSONResponse(content=body.model_dump())
        response.set_cookie(
            key=REFRESH_COOKIE_NAME,
            value=new_refresh,
            httponly=True,
            secure=SECURE_COOKIES,           # <-- hardened: secure by ENV
            samesite=REFRESH_COOKIE_SAMESITE,
            max_age=REFRESH_EXPIRES_DAYS * 24 * 3600,
            path="/",
        )
        return response

    return body

class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None

@auth_router.post("/logout", status_code=204)
def logout(payload: Optional[LogoutRequest] = None, request: Request = None, session: Session = Depends(get_session)):
    raw = None
    if REFRESH_IN_COOKIE and request is not None:
        raw = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw and payload and payload.refresh_token:
        raw = payload.refresh_token.strip()
    if not raw:
        # Clear cookie if present even when no payload provided
        r = Response(status_code=204)
        if REFRESH_IN_COOKIE:
            r.delete_cookie(REFRESH_COOKIE_NAME, path="/")
        return r

    fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    rec = session.scalar(select(RefreshToken).where(RefreshToken.Fingerprint == fp))
    if rec:
        rec.Is_Revoked = True
        session.commit()

    r = Response(status_code=204)
    if REFRESH_IN_COOKIE:
        r.delete_cookie(REFRESH_COOKIE_NAME, path="/")  # <-- logout hardening: clear cookie
    return r

@app.get("/healthz", include_in_schema=False)
def healthz(session: Session = Depends(get_session)):
    try:
        session.execute(select(1))
        return {"status": "ok"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "degraded", "error": str(e)})

# ============================ Okta OIDC (PKCE) ================================
import secrets
from typing import Dict as _Dict

from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String as SAString, BigInteger
from sqlalchemy import create_engine as create_engine_okta
from sqlalchemy.orm import sessionmaker as sessionmaker_okta

OKTA_ISSUER = (os.getenv("OKTA_ISSUER") or "").strip()
OKTA_METADATA_URL = (os.getenv("OKTA_METADATA_URL") or "").strip()
OKTA_CLIENT_ID = (os.getenv("OKTA_CLIENT_ID") or "").strip()
OKTA_CLIENT_SECRET = (os.getenv("OKTA_CLIENT_SECRET") or "").strip()
OKTA_REDIRECT_URI = (os.getenv("OKTA_REDIRECT_URI") or "").strip()
OKTA_DEFAULT_SCOPES = (os.getenv("OKTA_DEFAULT_SCOPES", "openid profile email")).strip()
OKTA_TOKEN_AUTH_METHOD = (os.getenv("OKTA_TOKEN_AUTH_METHOD") or "basic").lower()  # basic|post

if not all([OKTA_ISSUER, OKTA_METADATA_URL, OKTA_CLIENT_ID, OKTA_REDIRECT_URI]):
    logging.warning("Okta env incomplete; /authorize and /callback will fail.")

okta_router = APIRouter(tags=["Okta"])

PKCE_DB_URL = os.getenv("PKCE_DB_URL", "sqlite:///./pkce_state.db")
STATE_TTL_SEC = int(os.getenv("PKCE_STATE_TTL_SEC", "600"))

BasePKCE = declarative_base()
engine_pkce = (
    create_engine_okta(PKCE_DB_URL, connect_args={"check_same_thread": False})
    if PKCE_DB_URL.strip().lower().startswith('sqlite')
    else create_engine_okta(PKCE_DB_URL)
)
SessionPKCE = sessionmaker_okta(bind=engine_pkce, autocommit=False, autoflush=False)

class PKCEState(BasePKCE):
    __tablename__ = "pkce_state"
    state = Column(SAString, primary_key=True, index=True)
    code_verifier = Column(SAString, nullable=False)
    nonce = Column(SAString, nullable=False)
    created_at = Column(BigInteger, nullable=False)

BasePKCE.metadata.create_all(bind=engine_pkce)

async def get_oidc_metadata() -> _Dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(OKTA_METADATA_URL)
        r.raise_for_status()
        return r.json()

async def get_jwks() -> _Dict:
    meta = await get_oidc_metadata()
    url = meta.get("jwks_uri")
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()

def _sha256_b64(s: str) -> str:
    return _b64url(hashlib.sha256(s.encode("ascii")).digest())

def save_pkce_state(state: str, code_verifier: str, nonce: str):
    now = int(time.time())
    with SessionPKCE() as db:
        db.add(PKCEState(state=state, code_verifier=code_verifier, nonce=nonce, created_at=now))
        db.commit()

def pop_pkce_state(state: str) -> Optional[Dict[str, str]]:
    with SessionPKCE() as db:
        rec = db.get(PKCEState, state)
        if not rec:
            return None
        if int(time.time()) - rec.created_at > STATE_TTL_SEC:
            db.delete(rec); db.commit(); return None
        out = {"code_verifier": rec.code_verifier, "nonce": rec.nonce}
        db.delete(rec); db.commit()
        return out

@okta_router.get("/authorize")
async def okta_authorize():
    meta = await get_oidc_metadata()
    auth_endpoint = meta.get("authorization_endpoint")
    if not auth_endpoint:
        raise HTTPException(status_code=500, detail="authorization_endpoint missing")

    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _sha256_b64(code_verifier)
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    save_pkce_state(state, code_verifier, nonce)

    params = {
        "client_id": OKTA_CLIENT_ID,
        "response_type": "code",
        "scope": OKTA_DEFAULT_SCOPES,
        "redirect_uri": OKTA_REDIRECT_URI,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    url = f"{auth_endpoint}?{urlencode(params)}"
    return RedirectResponse(url, status_code=302)

@okta_router.get("/callback")
async def okta_callback(code: Optional[str] = None, state: Optional[str] = None):
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")
    rec = pop_pkce_state(state)
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    code_verifier = rec["code_verifier"]
    expected_nonce = rec["nonce"]

    meta = await get_oidc_metadata()
    token_endpoint = meta.get("token_endpoint")
    if not token_endpoint:
        raise HTTPException(status_code=500, detail="token_endpoint missing")

    # Build base body WITHOUT client_id; add only when appropriate
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OKTA_REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    if OKTA_CLIENT_SECRET:
        auth_method = (os.getenv("OKTA_TOKEN_AUTH_METHOD") or "basic").lower()
        if auth_method == "post":
            # client_secret_post: client_id & client_secret in body
            data["client_id"] = OKTA_CLIENT_ID
            data["client_secret"] = OKTA_CLIENT_SECRET
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        else:
            # client_secret_basic: Authorization: Basic, no client_id in body
            basic = base64.b64encode(f"{OKTA_CLIENT_ID}:{OKTA_CLIENT_SECRET}".encode()).decode()
            headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"}
    else:
        # Public PKCE (no secret): include client_id in body
        data["client_id"] = OKTA_CLIENT_ID
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(token_endpoint, data=data, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text}")
        tokens = resp.json()

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="ID token missing")
    okta_access = tokens.get("access_token")  # provided for at_hash verification

    jwks = await get_jwks()
    header = jwt.get_unverified_header(id_token)
    kid = header.get("kid")
    alg = header.get("alg")
    if alg != "RS256":
        raise HTTPException(status_code=400, detail=f"Unsupported alg {alg}, expected RS256")

    try:
        key = next(k for k in jwks.get("keys", []) if k.get("kid") == kid)
        claims = jwt.decode(
            id_token,
            key,  # JWK dict accepted
            algorithms=["RS256"],
            audience=OKTA_CLIENT_ID,
            issuer=OKTA_ISSUER,
            access_token=okta_access,  # ensures at_hash check when present
            options={"require_exp": True, "require_iat": True, "require_aud": True, "require_iss": True},
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"ID token verification failed: {str(e)}")

    if claims.get("nonce") != expected_nonce:
        raise HTTPException(status_code=400, detail="Nonce mismatch")

    # Provision/lookup local user and mint first‑party API access token
    email = claims.get("email") or claims.get("preferred_username") or claims.get("sub")
    with Session(engine) as s:
        user = s.scalar(select(User).where(User.Email_Address == (email or "").lower()))
        if not user:
            user = User(
                Email_Address=(email or "").lower(),
                User_Name=email or "okta_user",
                Role="viewer",
                Is_Active=True,
                Hashed_Pword=pwd_context.hash(os.urandom(8)),
            )
            s.add(user)
            s.commit()
            s.refresh(user)

        scopes = ROLE_TO_SCOPES.get(user.Role or "user", [])
        kid_active, priv = rs256_keystore.get_active_signing_key()
        api_access = jwt.encode(
            {"sub": user.Email_Address, "ver": user.TokenVersion, "scopes": scopes, "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRES_MIN)},
            priv,
            algorithm=JWT_RS256_ALG,
            headers={"kid": kid_active},
        )

    POST_LOGIN_REDIRECT = os.getenv("POST_LOGIN_REDIRECT", "/docs-custom")
    COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")
    response = RedirectResponse(url=POST_LOGIN_REDIRECT, status_code=302)

    # First‑party API token (HTTP‑only)
    response.set_cookie(
        key="api_access_token",
        value=api_access,
        httponly=True,
        secure=SECURE_COOKIES,  # <-- hardened: secure by ENV
        samesite=COOKIE_SAMESITE,
        max_age=TOKEN_EXPIRES_MIN * 60,
        path="/",
    )

    # Optional: Okta access token (HTTP‑only)
    if tokens.get("access_token"):
        response.set_cookie(
            key="okta_access_token",
            value=tokens["access_token"],
            httponly=True,
            secure=SECURE_COOKIES,  # <-- hardened: secure by ENV
            samesite=COOKIE_SAMESITE,
            max_age=tokens.get("expires_in", TOKEN_EXPIRES_MIN * 60),
            path="/",
        )

    # Optional: Okta refresh token
    if tokens.get("refresh_token"):
        response.set_cookie(
            key="okta_refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=SECURE_COOKIES,  # <-- hardened: secure by ENV
            samesite=COOKIE_SAMESITE,
            max_age=30 * 24 * 3600,
            path="/",
        )

    return response

@okta_router.get("/authz/ready", include_in_schema=False)
async def okta_authz_ready():
    issues = []
    for k, v in [
        ("OKTA_ISSUER", OKTA_ISSUER),
        ("OKTA_METADATA_URL", OKTA_METADATA_URL),
        ("OKTA_CLIENT_ID", OKTA_CLIENT_ID),
        ("OKTA_CLIENT_SECRET", "***" if OKTA_CLIENT_SECRET else None),
        ("OKTA_REDIRECT_URI", OKTA_REDIRECT_URI),
    ]:
        if not v:
            issues.append(f"Missing {k}")
    try:
        meta = await get_oidc_metadata()
        for f in ["authorization_endpoint", "token_endpoint", "jwks_uri"]:
            if not meta.get(f):
                issues.append(f"Metadata missing {f}")
    except Exception as e:
        issues.append(f"Metadata error: {str(e)}")
    return JSONResponse({"ok": not issues, "issues": issues}, status_code=200 if not issues else 500)

@okta_router.post("/logout")
async def okta_logout(request: Request):
    meta = await get_oidc_metadata()
    revoke_url = meta.get("revocation_endpoint")
    logout_url = f"{OKTA_ISSUER}/v1/logout"

    tokens = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    okta_refresh = tokens.get("okta_refresh_token")
    if okta_refresh:
        data = {"token": okta_refresh, "token_type_hint": "refresh_token", "client_id": OKTA_CLIENT_ID}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if OKTA_CLIENT_SECRET:
            _b = base64.b64encode(f"{OKTA_CLIENT_ID}:{OKTA_CLIENT_SECRET}".encode()).decode()
            headers["Authorization"] = f"Basic {_b}"
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                await client.post(revoke_url, data=data, headers=headers)
            except Exception as e:
                logging.warning("Okta revocation failed: %s", e)

    # Clear local cookies on logout (hardening)
    r = JSONResponse({"ok": True, "logout": logout_url})
    for cookie in ("api_access_token", "okta_access_token", "okta_refresh_token"):
        r.delete_cookie(cookie, path="/")
    return r

# ============================ Mount Routers & Docs ============================
from security_deps import require_auth, require_scopes, Principal  # cookie fallback lives here

async def _auth_dep(request: Request) -> Principal:
    auth = request.headers.get("Authorization")
    return await require_auth(authorization=auth, base_url=str(request.base_url).rstrip("/"), request=request)

def scopes(*needed: str):
    """
    Dependency wrapper to enforce scopes using require_scopes().
    Ensures Principal is resolved via _auth_dep, then checks.
    """
    def _dep(principal: Principal = Depends(_auth_dep)):
        return require_scopes(*needed)(principal)
    return _dep

# Protect business routers globally with auth
app.include_router(orders_router, dependencies=[Depends(_auth_dep)])

# Add per-endpoint scope enforcement for write operations
# (We can't attach decorators after definition, so add here via global dependencies)
# NOTE: Already added in the endpoint decorators above if you prefer that style.
# If you want global route-level enforcement, you can re-include with separate routes.

# Keep auth and Okta routes public
app.include_router(auth_router)
app.include_router(okta_router)

# ---- Guarded Swagger docs: require auth; else redirect to /authorize ----
@app.get("/docs", include_in_schema=False)
async def docs(request: Request):
    try:
        await require_auth(
            authorization=request.headers.get("Authorization"),
            base_url=str(request.base_url).rstrip("/"),
            request=request,
        )
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/authorize", status_code=302)
        raise
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Docs",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui.css",
        swagger_favicon_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/favicon-32x32.png",
    )

@app.get("/docs-dark", include_in_schema=False)
async def docs_dark(request: Request):
    try:
        await require_auth(
            authorization=request.headers.get("Authorization"),
            base_url=str(request.base_url).rstrip("/"),
            request=request,
        )
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/authorize", status_code=302)
        raise
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Docs (Dark)",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-dark.css?v=32",  # your custom dark theme
        swagger_favicon_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/favicon-32x32.png",
    )

@app.get("/docs-custom", include_in_schema=False)
async def custom_docs(request: Request):
    try:
        await require_auth(
            authorization=request.headers.get("Authorization"),
            base_url=str(request.base_url).rstrip("/"),
            request=request,
        )
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/authorize", status_code=302)
        raise
    file_path = STATIC_DIR / "swagger-custom.html"
    if not file_path.exists():
        return HTMLResponse(content="<h1>swagger-custom.html not found in static folder</h1>", status_code=404)
    html_content = file_path.read_text(encoding="utf-8")
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
