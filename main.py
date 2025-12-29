# SimpleAPI_SQLAlchemy_version.py 
""" 
API - SQLAlchemy + OAuth2/JWT (Beginner-friendly)
What this version adds:
 1) All endpoints are LOCKED by default.
 2) They UNLOCK only when you log in and pass a valid Bearer token.
 3) OAuth2 Password Flow with JWT access tokens.
 4) Token expires in 60 minutes (configurable).
 5) POST /Register : Register a new user (public).
 6) POST /token : Login to get an access token (public).
 7) GET /me : Example protected endpoint for quick testing.

**NEW in this update**
 8) Refresh token hygiene: rotation + revocation.
 9) /token/refresh endpoint that rotates refresh tokens and detects reuse.
10) Optional cookie-based refresh token delivery via env flags.

Run locally:
 uvicorn main:app --reload --port 8000 
"""
import httpx
import os 
import time 
import logging 
import hashlib
from datetime import datetime, timedelta, timezone 
from pathlib import Path 
from typing import Iterator, List, Optional, Tuple, Dict 
from dotenv import load_dotenv # pip install python-dotenv 
from fastapi import FastAPI, Request, Depends, HTTPException, status, Query, APIRouter 
from fastapi.responses import HTMLResponse, JSONResponse, Response 
from fastapi.staticfiles import StaticFiles 
from fastapi.middleware.cors import CORSMiddleware 
from fastapi.openapi.docs import get_swagger_ui_html 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from pydantic import BaseModel, EmailStr, Field 
from sqlalchemy import Boolean, Integer, String, create_engine, select, or_, cast
from sqlalchemy import DateTime, func, UniqueConstraint
from sqlalchemy.exc import IntegrityError 
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column 
# Security imports (OAuth2 + JWT + password hashing) 
from passlib.context import CryptContext 
from jose import JWTError, jwt # pip install "python-jose[cryptography]" 
# Rate limit imports 
from slowapi import Limiter 
from slowapi.util import get_remote_address 
from slowapi.errors import RateLimitExceeded 
from slowapi.middleware import SlowAPIMiddleware # Proper SlowAPI wiring 

# --- Error payload model for consistent JSON in Swagger --- 
class ErrorDetail(BaseModel): 
    code: str 
    message: str 
    attempts_remaining: Optional[int] = None 
    retry_after_seconds: Optional[int] = None 

# --- Simple sticky attempt counter to enrich 400s with "attempts remaining" --- 
# Keep this aligned with your SlowAPI limit of 3/min 
LOGIN_MAX_ATTEMPTS = 3 
LOGIN_WINDOW_SECONDS = 60 
_attempts: dict[Tuple[str, str], list[float]] = {} # key -> timestamps 

def _attempts_key(username: str, ip: str) -> Tuple[str, str]: 
    return (username or "", ip or "") 

def get_attempts_remaining(username: str, ip: str) -> int: 
    now = time.time() 
    key = _attempts_key(username, ip) 
    arr = _attempts.setdefault(key, []) 
    # prune older than window 
    arr[:] = [t for t in arr if now - t <= LOGIN_WINDOW_SECONDS] 
    return max(0, LOGIN_MAX_ATTEMPTS - len(arr)) 

def note_failed_attempt(username: str, ip: str) -> int: 
    now = time.time() 
    key = _attempts_key(username, ip) 
    arr = _attempts.setdefault(key, []) 
    arr.append(now) 
    # prune outside window 
    arr[:] = [t for t in arr if now - t <= LOGIN_WINDOW_SECONDS] 
    return max(0, LOGIN_MAX_ATTEMPTS - len(arr)) 

def clear_attempts(username: str, ip: str) -> None: 
    key = _attempts_key(username, ip) 
    if key in _attempts: 
        _attempts[key] = [] 

# Map role to scopes (single authoritative source) 
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

# ============================ Security Config ================================ 
# For study/demo purposes only—use environment variables in production! 
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me") 
ALGORITHM = os.getenv("ALGORITHM", "HS256") 
TOKEN_EXPIRES_MIN = int(os.getenv("TOKEN_EXPIRES_MIN", "60")) 

# ============================ Refresh Token Config ============================
REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", "30"))  # default 30 days
REFRESH_IN_COOKIE = os.getenv("REFRESH_IN_COOKIE", "false").lower() == "true"  # optional
REFRESH_COOKIE_NAME = os.getenv("REFRESH_COOKIE_NAME", "refresh_token")
REFRESH_COOKIE_SECURE = os.getenv("REFRESH_COOKIE_SECURE", "true").lower() == "true"
REFRESH_COOKIE_SAMESITE = os.getenv("REFRESH_COOKIE_SAMESITE", "strict").lower()  # strict|lax|none

# Password hashing context (bcrypt + argon2 if installed) 
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto") 

# Tell FastAPI where the token endpoint lives (for Swagger's "Authorize" button) 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token") 

# ============================ App & CORS ========================== 
app = FastAPI( 
    title="API - Swagger UI - Beta Version", 
    version="0.1.0", 
    description=( 
        "<h3>Citation/References</h3>" 
        "<blockquote>Author: http://www.linkedin.com/in/fernando-losantos-33a746124/</blockquote>" 
    ), 
) 

# Initialize limiter (after `app = FastAPI(...)`) 
# Use per-user identity if request.state.user_email is set; otherwise fall back to IP. 
limiter = Limiter( 
    key_func=lambda request: ( 
        getattr(request.state, "user_email", None) or get_remote_address(request) 
    ) 
) 
# Proper SlowAPI wiring 
app.state.limiter = limiter 
app.add_middleware(SlowAPIMiddleware) 

# Global handler for 429 
@app.exception_handler(RateLimitExceeded) 
async def rate_limit_handler(request, exc: RateLimitExceeded): 
    retry_after = int(60 - (time.time() % 60)) or 1 
    return JSONResponse( 
        status_code=status.HTTP_429_TOO_MANY_REQUESTS, 
        content={ 
            "code": "too_many_requests", 
            "message": "Too many failed login attempts. Try again later." 
            if str(request.url.path).lower() == "/token" else "Too many requests.", 
            "retry_after_seconds": retry_after, 
        }, 
        headers={"Retry-After": str(retry_after)}, 
    ) 

# Load environment variables from .env (dev convenience) 
load_dotenv() 

# ============================ RS256 Key Management ============================= 
import base64 
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey 

JWT_RS256_ALG = "RS256" 

def _b64url(b: bytes) -> str: 
    """Base64url encode without padding.""" 
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii") 

def _normalize_pem(text: str) -> str: 
    """Accepts PEM in normal multiline or single-line with \\n escapes; returns normalized PEM.""" 
    return text.replace("\\n", "\n") if "\\n" in text else text 

def _b64_to_text(s: str) -> str: 
    """Decode a Base64 environment value to UTF-8 text.""" 
    s = (s or "").strip().strip('"') 
    return base64.b64decode(s).decode("utf-8") 

class RS256KeyStore: 
    """ 
    Holds multiple RS256 keys by KID. 
    - active_kid: which KID is used to sign new tokens 
    - priv_by_kid: private PEMs for signing 
    - pub_by_kid: public PEMs for verification & JWKS 
    """ 
    def __init__(self): 
        self.active_kid: Optional[str] = os.getenv("JWT_ACTIVE_KID", "").strip() or None 
        self.priv_by_kid: Dict[str, str] = {} 
        self.pub_by_kid: Dict[str, str] = {} 
        self._load_env() 

    def _load_env(self): 
        # First load Base64-encoded PEMs (preferred in cloud deployments like Render) 
        for k, v in os.environ.items(): 
            if k.startswith("JWT_RS256_PRIVATE_KEY_B64__"): 
                kid = k.split("__", 1)[1] 
                self.priv_by_kid[kid] = _b64_to_text(v) 
            elif k.startswith("JWT_RS256_PUBLIC_KEY_B64__"): 
                kid = k.split("__", 1)[1] 
                self.pub_by_kid[kid] = _b64_to_text(v) 
        # Then load inline PEMs (with \n escapes) only if Base64 wasn't provided 
        for k, v in os.environ.items(): 
            if k.startswith("JWT_RS256_PRIVATE_KEY__"): 
                kid = k.split("__", 1)[1] 
                self.priv_by_kid.setdefault(kid, _normalize_pem(v.strip().strip('"'))) 
            elif k.startswith("JWT_RS256_PUBLIC_KEY__"): 
                kid = k.split("__", 1)[1] 
                self.pub_by_kid.setdefault(kid, _normalize_pem(v.strip().strip('"'))) 
        # If active_kid not set but we have private keys, pick the last one deterministically 
        if not self.active_kid and self.priv_by_kid: 
            self.active_kid = sorted(self.priv_by_kid.keys())[-1] 

    def get_active_signing_key(self) -> Tuple[str, str]: 
        """Return (kid, private_pem) for signing; raise if missing.""" 
        if not self.active_kid:
            raise RuntimeError("JWT_ACTIVE_KID is not set") 
        priv = self.priv_by_kid.get(self.active_kid) 
        if not priv:
            raise RuntimeError(f"No private key configured for kid={self.active_kid}") 
        return self.active_kid, priv 

    def get_public_key(self, kid: str) -> Optional[str]: 
        """Return public PEM for a given kid; None if unknown.""" 
        return self.pub_by_kid.get(kid) 

    def jwks(self) -> dict: 
        """ 
        Return JWKS with all configured RSA public keys. 
        Never raises; skips bad keys and logs the reason. 
        """ 
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
                continue 
        return {"keys": keys} 

# Create a global keystore instance (available to routes below) 
rs256_keystore = RS256KeyStore() 

BASE_DIR = Path(__file__).resolve().parent 
STATIC_DIR = BASE_DIR / "static" 
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static") 

raw_origins = os.getenv("CORS_ORIGINS", "") 
allow_origins: List[str] = [o.strip() for o in raw_origins.split(",") if o.strip()] 
ENV = os.getenv("ENV", "dev").lower() 
if ENV == "prod" and not allow_origins: 
    # In production, require explicit origins. 
    raise RuntimeError("CORS_ORIGINS must be set in production (comma-separated list).") 
# In dev, you can allow everything, but only if explicitly requested 
if ENV != "prod" and not allow_origins: 
    allow_origins = ["http://localhost:8000", "http://127.0.0.1:8000"] # dev-friendly defaults 
app.add_middleware( 
    CORSMiddleware, 
    allow_origins=allow_origins, 
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], 
    allow_headers=["*"], 
    expose_headers=["*"], 
) 

# ============================ Database (PostgreSQL) ========================== 
DATABASE_URL = os.getenv("DB_URL", "").strip() 
if not DATABASE_URL: 
    raise RuntimeError("DB_URL is not set. Put it in .env or environment variables.") 
# Tip: ensure your .env uses a real '&' (not '&amp;') in the query string. 
engine = create_engine( 
    DATABASE_URL, 
    echo=False, 
    future=True, 
    pool_pre_ping=True, # helps recover stale connections 
) 

class Base(DeclarativeBase): 
    """Base class for ORM models.""" 

# ------------------------------ ORM MODELS (SQLAlchemy) ------------------------------ 
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

# NEW: RefreshToken model
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

# ============================ Session dependency ============================= 

def get_session() -> Iterator[Session]: 
    with Session(engine) as session: 
        yield session 

# ============================ Schemas (Pydantic) ============================= 
# orders 
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

# customers 
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

# Users 
class UserCreate(BaseModel): 
    User_Name: str 
    Location_Address: Optional[str] = None 
    Email_Address: EmailStr 
    Contact_Number: Optional[str] = None 
    Vat_Number: Optional[str] = None 
    Password: str = Field(..., min_length=6, description="Strong password") 

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

from pydantic import BaseModel, EmailStr, Field # (duplicate import kept for consistency) 

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

# invoices 
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

# agreements 
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

# Tokens 
class Token(BaseModel): 
    access_token: str 
    token_type: str = "bearer" 
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None  # seconds (for access token)

class TokenData(BaseModel): 
    email: Optional[str] = None 



@app.get("/_debug/routes", include_in_schema=False)
def list_routes():
    return [
        {"path": r.path, "name": r.name, "methods": list(r.methods or [])}
        for r in app.router.routes
    ]

@app.get("/authz/debug", include_in_schema=False)
def authz_debug():
    return {
        "OKTA_CLIENT_ID": OKTA_CLIENT_ID,
        "OKTA_REDIRECT_URI": OKTA_REDIRECT_URI
    }

# ------------------------------- Swagger UI (dark) ------------------------------- 
@app.get("/docs-dark", include_in_schema=False) 
def docs_dark(): 
    return get_swagger_ui_html( 
        openapi_url=app.openapi_url, 
        title=f"{app.title} - Docs (Dark)", 
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-bundle.js", 
        swagger_css_url="/static/swagger-dark.css?v=32", 
        swagger_favicon_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/favicon-32x32.png", 
    ) 

# ====================== AUTH HELPERS (hash, verify, JWT) ===================== 

def get_password_hash(password: str) -> str: 
    """Return a bcrypt/argon2 hash for secure storage.""" 
    return pwd_context.hash(password) 


def verify_password(plain_password: str, hashed_password: str) -> bool: 
    """Check a plaintext password against its hash.""" 
    return pwd_context.verify(plain_password, hashed_password) 


def create_access_token(data: dict, expires_minutes: int = TOKEN_EXPIRES_MIN) -> str: 
    """Create an RS256-signed JWT with exp/nbf claims and a kid header.""" 
    now = datetime.now(timezone.utc) 
    to_encode = data.copy() 
    expire = now + timedelta(minutes=expires_minutes) 
    to_encode.update({"exp": expire, "nbf": now - timedelta(seconds=5)}) 
    kid, private_pem = rs256_keystore.get_active_signing_key() 
    return jwt.encode(to_encode, private_pem, algorithm=JWT_RS256_ALG, headers={"kid": kid}) 

# ====================== Refresh Token Helpers ======================

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _gen_refresh_token_raw() -> str:
    # 32 bytes → base64url without padding
    b = os.urandom(32)
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _fp_sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _hash_refresh(raw: str) -> str:
    # Argon2id/bcrypt via passlib pwd_context (same as passwords)
    return pwd_context.hash(raw)


def issue_refresh_token(session: Session, user: User) -> str:
    """Create a new refresh token (single active per user), revoke prior active tokens, and persist."""
    # Revoke existing active tokens for this user
    for rt in session.scalars(select(RefreshToken).where(RefreshToken.User_Id == user.User_Id, RefreshToken.Is_Revoked == False)).all():
        rt.Is_Revoked = True

    raw = _gen_refresh_token_raw()
    fp = _fp_sha256(raw)
    hashed = _hash_refresh(raw)
    expires = _now_utc() + timedelta(days=REFRESH_EXPIRES_DAYS)

    rec = RefreshToken(
        User_Id=user.User_Id,
        Token_Hash=hashed,
        Fingerprint=fp,
        Expires_At=expires,
        TokenVersionAtIssue=int(user.TokenVersion or 1),
        Is_Revoked=False,
    )
    session.add(rec)
    session.commit()
    return raw


def find_refresh_record_by_fp(session: Session, fp_hex: str) -> Optional[RefreshToken]:
    return session.scalar(select(RefreshToken).where(RefreshToken.Fingerprint == fp_hex))


def revoke_all_user_refresh_tokens(session: Session, user: User):
    for rt in session.scalars(select(RefreshToken).where(RefreshToken.User_Id == user.User_Id)).all():
        rt.Is_Revoked = True
    session.commit()


def get_user_by_email(session: Session, email: str) -> Optional[User]: 
    return session.scalar(select(User).where(User.Email_Address == email)) 


def get_current_user( 
    token: str = Depends(oauth2_scheme), 
    session: Session = Depends(get_session), 
) -> User: 
    credentials_error = HTTPException( 
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Could not validate credentials (invalid or expired token)", 
        headers={"WWW-Authenticate": "Bearer"}, 
    ) 
    try: 
        payload = None 
        # Try RS256 first (read 'kid' from header) 
        try: 
            header = jwt.get_unverified_header(token) 
            kid = header.get("kid") 
        except Exception: 
            kid = None 
        if kid: 
            pub_pem = rs256_keystore.get_public_key(kid) 
            if pub_pem: 
                payload = jwt.decode(token, pub_pem, algorithms=[JWT_RS256_ALG]) 
        # TEMP: HS256 legacy decode during migration (controlled by env) 
        if payload is None and os.getenv("ALLOW_HS256_DECODE", "false").lower() == "true": 
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) 
        if payload is None: 
            raise credentials_error 
        email = payload.get("sub") 
        token_ver = payload.get("ver") 
        scopes = payload.get("scopes", []) 
        if email is None or token_ver is None: 
            raise credentials_error 
        user = get_user_by_email(session, email) 
        if user is None or not user.Is_Active: 
            raise credentials_error 
        if token_ver != user.TokenVersion: 
            raise HTTPException(status_code=401, detail="Token revoked") 
        user.Scopes = scopes 
        return user 
    except JWTError: 
        raise credentials_error 
    except HTTPException: 
        raise 
    except Exception as e: 
        logging.error(f"Token validation failed: {e}") 
        raise credentials_error 


def set_rate_limit_identity(request: Request, current_user: User = Depends(get_current_user)):
    """Attach the authenticated user's email so the limiter can use a per-user key.""" 
    request.state.user_email = current_user.Email_Address 


def require_role(allowed_roles: list[str]): 
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.Role not in allowed_roles: 
            raise HTTPException(status_code=403, detail="Insufficient permissions") 
        return current_user 
    return role_checker 

# --- Scope-based authorization (route-level) --- 

def require_scopes(required: list[str]): 
    """Ensure the current user's JWT contains all required scopes.""" 
    def checker(current_user: User = Depends(get_current_user)):
        scopes = set(getattr(current_user, "Scopes", [])) 
        if not set(required).issubset(scopes): 
            raise HTTPException(status_code=403, detail="Insufficient scope") 
        return current_user 
    return checker 

# ================================ ROUTERS-ENDPOINTS ================================ 
# orders 
orders_router = APIRouter(tags=["Orders"]) 
responses204 = {204: {"description": "Deleted successfully", "content": {}}} 

@orders_router.get("/GetOrder/{Order_Number}", response_model=OrderOut) 
@limiter.limit("50/minute") 
def get_order( 
    request: Request, 
    Order_Number: int, 
    session: Session = Depends(get_session), 
) -> OrderOut: 
    o = session.get(Order, Order_Number) 
    if not o: 
        raise HTTPException(status_code=404, detail="Order not found") 
    return order_out(o) 

@orders_router.get("/ListOrders", response_model=List[OrderOut]) 
@limiter.limit("50/minute") 
def list_orders( 
    request: Request, 
    Order_Number: Optional[int] = None, 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[OrderOut]: 
    stmt = select(Order) 
    if Order_Number is not None: 
        stmt = stmt.where(Order.Order_Number == Order_Number) 
    stmt = stmt.order_by(Order.Order_Number).limit(limit).offset(offset) # pagination 
    return [order_out(o) for o in session.scalars(stmt).all()] 

@orders_router.get("/SearchOrder", response_model=List[OrderOut]) 
@limiter.limit("50/minute") 
def search_order( 
    request: Request, 
    SQRY: Optional[str] = Query(None, description="Search across all fields"), 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
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
        stmt = stmt.order_by(Order.Order_Number).limit(limit).offset(offset) # pagination 
        results = session.scalars(stmt).all() 
        return [order_out(o) for o in results] 
    except Exception as e: 
        logging.error(f"Search order failed: {e}") 
        raise HTTPException(status_code=500, detail=f"Search order failed: {str(e)}") 

@orders_router.post("/CreateOrders", response_model=List[OrderOut], status_code=201) 
@limiter.limit("50/minute") 
def create_orders( 
    request: Request, 
    payload: List[OrderIn], 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["orders:write"])), 
): 
    created = [] 
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

@orders_router.put("/UpdateOrders/{Order_Number}", response_model=OrderOut) 
@limiter.limit("50/minute") 
def update_order( 
    request: Request, 
    Order_Number: int, 
    payload: OrderIn, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["orders:write"])), 
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

@orders_router.delete("/DeleteOrders/{Order_Number}", status_code=204, response_class=Response, responses=responses204) 
@limiter.limit("50/minute") 
def delete_order( 
    request: Request, 
    Order_Number: int, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["orders:write"])), 
) -> Response: 
    o = session.get(Order, Order_Number) 
    if not o: 
        raise HTTPException(status_code=404, detail="Order not found") 
    session.delete(o) 
    session.commit() 
    return Response(status_code=204) 

# customers 
customers_router = APIRouter(tags=["Customers"]) 

@customers_router.get("/GetCustomer/{Customer_Number}", response_model=CustomerOut) 
@limiter.limit("50/minute") 
def get_customer( 
    request: Request, 
    Customer_Number: int, 
    session: Session = Depends(get_session), 
) -> CustomerOut: 
    c = session.get(Customer, Customer_Number) 
    if not c: 
        raise HTTPException(status_code=404, detail="Customer not found") 
    return customer_out(c) 

@customers_router.get("/ListCustomers", response_model=List[CustomerOut]) 
@limiter.limit("50/minute") 
def list_customers( 
    request: Request, 
    Customer_Number: Optional[int] = None, 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[CustomerOut]: 
    stmt = select(Customer) 
    if Customer_Number is not None: 
        stmt = stmt.where(Customer.Customer_Number == Customer_Number) 
    stmt = stmt.order_by(Customer.Customer_Number).limit(limit).offset(offset) # pagination 
    return [customer_out(c) for c in session.scalars(stmt).all()] 

@customers_router.get("/SearchCustomer", response_model=List[CustomerOut]) 
@limiter.limit("50/minute") 
def search_customer( 
    request: Request, 
    SQRY: Optional[str] = Query(None, description="Search across all fields"), 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[CustomerOut]: 
    try: 
        stmt = select(Customer) 
        if SQRY: 
            search_term = f"%{SQRY}%" 
            stmt = stmt.where( 
                or_( 
                    cast(Customer.Customer_Number, String).ilike(search_term), 
                    cast(Customer.Customer_Name, String).ilike(search_term), 
                    cast(Customer.Customer_Address, String).ilike(search_term), 
                    cast(Customer.Contact_Number, String).ilike(search_term), 
                    cast(Customer.Email_Address, String).ilike(search_term), 
                ) 
            ) 
        stmt = stmt.order_by(Customer.Customer_Number).limit(limit).offset(offset) # pagination 
        results = session.scalars(stmt).all() 
        return [customer_out(c) for c in results] 
    except Exception as e: 
        logging.error(f"Search customer failed: {e}") 
        raise HTTPException(status_code=500, detail=f"Search customer failed: {str(e)}") 

@customers_router.post("/CreateCustomers", response_model=List[CustomerOut], status_code=201) 
@limiter.limit("50/minute") 
def create_customer( 
    request: Request, 
    payload: List[CustomerIn], 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["customers:write"])), 
): 
    created = [] 
    for item in payload: 
        c = Customer(**item.model_dump()) 
        session.add(c) 
        created.append(c) 
    try: 
        session.commit() 
    except IntegrityError: 
        session.rollback() 
        raise HTTPException(status_code=409, detail="Customer already exists") 
    except Exception as e: 
        session.rollback() 
        logging.exception("Create customer failed") 
        raise HTTPException(status_code=500, detail=f"Create customer failed: {e}") 
    for c in created: 
        session.refresh(c) 
    return [customer_out(c) for c in created] 

@customers_router.put("/UpdateCustomers/{Customer_Number}", response_model=CustomerOut) 
@limiter.limit("50/minute") 
def update_customer( 
    request: Request, 
    Customer_Number: int, 
    payload: CustomerIn, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["customers:write"])), 
) -> CustomerOut: 
    c = session.get(Customer, Customer_Number) 
    if not c: 
        raise HTTPException(status_code=404, detail="Customer not found") 
    c.Customer_Name = payload.Customer_Name 
    c.Customer_Address = payload.Customer_Address 
    c.Contact_Number = payload.Contact_Number 
    c.Email_Address = payload.Email_Address 
    try: 
        session.commit() 
    except IntegrityError: 
        session.rollback() 
        raise HTTPException(status_code=409, detail="Customer already exists") 
    session.refresh(c) 
    return customer_out(c) 

@customers_router.delete("/DeleteCustomers/{Customer_Number}", status_code=204, response_class=Response, responses=responses204) 
@limiter.limit("50/minute") 
def delete_customer( 
    request: Request, 
    Customer_Number: int, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["customers:write"])), 
) -> Response: 
    c = session.get(Customer, Customer_Number) 
    if not c: 
        raise HTTPException(status_code=404, detail="Customer not found") 
    session.delete(c) 
    session.commit() 
    return Response(status_code=204) 

# invoices 
invoices_router = APIRouter(tags=["Invoices"]) 

@invoices_router.get("/GetInvoice/{Invoice_Number}", response_model=InvoiceOut) 
@limiter.limit("50/minute") 
def get_invoice( 
    request: Request, 
    Invoice_Number: int, 
    session: Session = Depends(get_session), 
) -> InvoiceOut: 
    i = session.get(Invoice, Invoice_Number) 
    if not i: 
        raise HTTPException(status_code=404, detail="Invoice not found") 
    return invoice_out(i) 

@invoices_router.get("/ListInvoices", response_model=List[InvoiceOut]) 
@limiter.limit("50/minute") 
def list_invoices( 
    request: Request, 
    invoice_number: Optional[int] = None, 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[InvoiceOut]: 
    stmt = select(Invoice) 
    if invoice_number is not None: 
        stmt = stmt.where(Invoice.Invoice_Number == invoice_number) 
    stmt = stmt.order_by(Invoice.Invoice_Number).limit(limit).offset(offset) # pagination 
    return [invoice_out(i) for i in session.scalars(stmt).all()] 

@invoices_router.get("/SearchInvoice", response_model=List[InvoiceOut]) 
@limiter.limit("50/minute") 
def search_invoice( 
    request: Request, 
    SQRY: Optional[str] = Query(None, description="Search across all fields"), 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[InvoiceOut]: 
    try: 
        stmt = select(Invoice) 
        if SQRY: 
            search_term = f"%{SQRY}%" 
            stmt = stmt.where( 
                or_( 
                    cast(Invoice.Invoice_Number, String).ilike(search_term), 
                    cast(Invoice.Customer_Number, String).ilike(search_term), 
                    cast(Invoice.Order_Number, String).ilike(search_term), 
                    cast(Invoice.Invoice_Date, String).ilike(search_term), 
                    cast(Invoice.Invoice_Email, String).ilike(search_term), 
                    cast(Invoice.Amount, String).ilike(search_term), 
                ) 
            ) 
        stmt = stmt.order_by(Invoice.Invoice_Number).limit(limit).offset(offset) 
        results = session.scalars(stmt).all() 
        return [invoice_out(i) for i in results] 
    except Exception as e: 
        logging.error(f"Search invoice failed: {e}") 
        raise HTTPException(status_code=500, detail=f"Search invoice failed: {str(e)}") 

@invoices_router.post("/CreateInvoices", response_model=List[InvoiceOut], status_code=201) 
@limiter.limit("50/minute") 
def create_invoices( 
    request: Request, 
    payload: List[InvoiceIn], 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["invoices:write"])), 
): 
    created = [] 
    for item in payload: 
        i = Invoice(**item.model_dump()) 
        session.add(i) 
        created.append(i) 
    try: 
        session.commit() 
    except IntegrityError: 
        session.rollback() 
        raise HTTPException(status_code=409, detail="Invoice already exists") 
    except Exception as e: 
        session.rollback() 
        logging.exception("Create invoice failed") 
        raise HTTPException(status_code=500, detail=f"Create invoice failed: {e}") 
    for i in created: 
        session.refresh(i) 
    return [invoice_out(i) for i in created] 

@invoices_router.put("/UpdateInvoices/{Invoice_Number}", response_model=InvoiceOut) 
@limiter.limit("50/minute") 
def update_invoice( 
    request: Request, 
    Invoice_Number: int, 
    payload: InvoiceIn, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["invoices:write"])), 
) -> InvoiceOut: 
    i = session.get(Invoice, Invoice_Number) 
    if not i: 
        raise HTTPException(status_code=404, detail="Invoice not found") 
    i.Order_Number = payload.Order_Number 
    i.Invoice_Date = payload.Invoice_Date 
    i.Invoice_Email = payload.Invoice_Email 
    i.Amount = payload.Amount 
    i.Customer_Number = payload.Customer_Number 
    try: 
        session.commit() 
    except IntegrityError: 
        session.rollback() 
        raise HTTPException(status_code=409, detail="Invoice already exists") 
    session.refresh(i) 
    return invoice_out(i) 

@invoices_router.delete("/DeleteInvoices/{Invoice_Number}", status_code=204, response_class=Response, responses=responses204) 
@limiter.limit("50/minute") 
def delete_invoice( 
    request: Request, 
    Invoice_Number: int, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["invoices:write"])), 
) -> Response: 
    i = session.get(Invoice, Invoice_Number) 
    if not i: 
        raise HTTPException(status_code=404, detail="Invoice not found") 
    session.delete(i) 
    session.commit() 
    return Response(status_code=204) 

# agreements 
agreements_router = APIRouter(tags=["Agreements"]) 

@agreements_router.get("/GetAgreement/{Agreement_number}", response_model=AgreementOut) 
@limiter.limit("50/minute") 
def get_agreement( 
    request: Request, 
    Agreement_number: str, 
    session: Session = Depends(get_session), 
) -> AgreementOut: 
    a = session.get(Agreement, Agreement_number) 
    if not a: 
        raise HTTPException(status_code=404, detail="Agreement not found") 
    return agreement_out(a) 

@agreements_router.get("/ListAgreements", response_model=List[AgreementOut]) 
@limiter.limit("50/minute") 
def list_agreements( 
    request: Request, 
    Agreement_number: Optional[str] = None, 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[AgreementOut]: 
    stmt = select(Agreement) 
    if Agreement_number is not None: 
        stmt = stmt.where(Agreement.Agreement_number == Agreement_number) 
    stmt = stmt.order_by(Agreement.Agreement_number).limit(limit).offset(offset) # pagination 
    return [agreement_out(a) for a in session.scalars(stmt).all()] 

@agreements_router.get("/SearchAgreements", response_model=List[AgreementOut]) 
@limiter.limit("50/minute") 
def search_agreements( 
    request: Request, 
    SQRY: Optional[str] = Query(None, description="Search across all fields"), 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[AgreementOut]: 
    try: 
        stmt = select(Agreement) 
        if SQRY: 
            search_term = f"%{SQRY}%" 
            stmt = stmt.where( 
                or_( 
                    Agreement.Agreement_number.ilike(search_term), 
                    cast(Agreement.Customer_Number, String).ilike(search_term), 
                    cast(Agreement.Customer_site, String).ilike(search_term), 
                    cast(Agreement.Your_reference_1, String).ilike(search_term), 
                    cast(Agreement.Telephone_number_1, String).ilike(search_term), 
                    cast(Agreement.customers_order_number, String).ilike(search_term), 
                    cast(Agreement.Agreement_order_type, String).ilike(search_term), 
                    Agreement.Termination_date.ilike(search_term), 
                    cast(Agreement.Line_charge_model, String).ilike(search_term), 
                    Agreement.Address_line_1.ilike(search_term), 
                    Agreement.Address_line_2.ilike(search_term), 
                    Agreement.Address_line_3.ilike(search_term), 
                    Agreement.Address_line_4.ilike(search_term), 
                    Agreement.Salesperson.ilike(search_term), 
                    cast(Agreement.Minimum_rental_type, String).ilike(search_term), 
                    cast(Agreement.Minimum_order_value, String).ilike(search_term), 
                    Agreement.Currency.ilike(search_term), 
                    Agreement.Reason_code_created_agreement.ilike(search_term), 
                    Agreement.User.ilike(search_term), 
                    cast(Agreement.Minimum_hire_period, String).ilike(search_term), 
                    Agreement.Payment_terms.ilike(search_term), 
                    Agreement.Price_list.ilike(search_term), 
                    Agreement.Reason_code_terminated_agreement.ilike(search_term), 
                    Agreement.Project_number.ilike(search_term), 
                ) 
            ) 
        stmt = stmt.order_by(Agreement.Agreement_number).limit(limit).offset(offset) # pagination 
        results = session.scalars(stmt).all() 
        return [agreement_out(a) for a in results] 
    except Exception as e: 
        logging.error(f"Search agreement failed: {e}") 
        raise HTTPException(status_code=500, detail=f"Search agreement failed: {str(e)}") 

@agreements_router.post("/CreateAgreements", response_model=List[AgreementOut], status_code=201) 
@limiter.limit("50/minute") 
def create_agreement( 
    request: Request, 
    payload: List[AgreementIn], 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["agreements:write"])), 
): 
    created = [] 
    for item in payload: 
        a = Agreement(**item.model_dump()) 
        session.add(a) 
        created.append(a) 
    try: 
        session.commit() 
    except IntegrityError: 
        session.rollback() 
        raise HTTPException(status_code=409, detail="Agreement already exists") 
    except Exception as e: 
        session.rollback() 
        logging.exception("Create order failed") 
        raise HTTPException(status_code=500, detail=f"Agreement create failed: {e}") 
    for a in created: 
        session.refresh(a) 
    return [agreement_out(a) for a in created] 

@agreements_router.put("/UpdateAgreements/{Agreement_number}", response_model=AgreementOut) 
@limiter.limit("50/minute") 
def update_agreement( 
    request: Request, 
    Agreement_number: str, 
    payload: AgreementIn, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["agreements:write"])), 
) -> AgreementOut: 
    a = session.get(Agreement, Agreement_number) 
    if not a: 
        raise HTTPException(status_code=404, detail="Agreement not found") 
    a.Customer_Number = payload.Customer_Number 
    a.Customer_site = payload.Customer_site 
    a.Your_reference_1 = payload.Your_reference_1 
    a.Telephone_number_1 = payload.Telephone_number_1 
    a.customers_order_number = payload.customers_order_number 
    a.Agreement_order_type = payload.Agreement_order_type 
    a.Termination_date = payload.Termination_date 
    a.Line_charge_model = payload.Line_charge_model 
    a.Address_line_1 = payload.Address_line_1 
    a.Address_line_2 = payload.Address_line_2 
    a.Address_line_3 = payload.Address_line_3 
    a.Address_line_4 = payload.Address_line_4 
    a.Salesperson = payload.Salesperson 
    a.Minimum_rental_type = payload.Minimum_rental_type 
    a.Minimum_order_value = payload.Minimum_order_value 
    a.Currency = payload.Currency 
    a.Reason_code_created_agreement = payload.Reason_code_created_agreement 
    a.User = payload.User 
    a.Minimum_hire_period = payload.Minimum_hire_period 
    a.Payment_terms = payload.Payment_terms 
    a.Price_list = payload.Price_list 
    a.Reason_code_terminated_agreement = payload.Reason_code_terminated_agreement 
    a.Project_number = payload.Project_number 
    try: 
        session.commit() 
    except IntegrityError: 
        session.rollback() 
        raise HTTPException(status_code=409, detail="Agreement already exists") 
    session.refresh(a) 
    return agreement_out(a) 

@agreements_router.delete("/DeleteAgreement/{Agreement_number}", status_code=204, response_class=Response, responses=responses204) 
@limiter.limit("50/minute") 
def delete_agreement( 
    request: Request, 
    Agreement_number: str, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["agreements:write"])), 
) -> Response: 
    a = session.get(Agreement, Agreement_number) 
    if not a: 
        raise HTTPException(status_code=404, detail="Agreement not found") 
    session.delete(a) 
    session.commit() 
    return Response(status_code=204) 

# Users 
users_router = APIRouter(tags=["Users"]) 

@users_router.get("/GetUser/{email}", response_model=UserPublic) 
@limiter.limit("50/minute") 
def get_user( 
    request: Request, 
    email: str, 
    session: Session = Depends(get_session), 
) -> UserPublic: 
    normalized_email = email.strip().lower() 
    u = session.scalar(select(User).where(User.Email_Address == normalized_email)) 
    if not u: 
        raise HTTPException(status_code=404, detail="User not found") 
    return user_out(u) 

@users_router.get("/ListUsers", response_model=List[UserPublic]) 
@limiter.limit("50/minute") 
def list_users( 
    request: Request, 
    email: Optional[str] = None, 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[UserPublic]: 
    stmt = select(User) 
    if email: 
        stmt = stmt.where(User.Email_Address == email.strip().lower()) 
    stmt = stmt.order_by(User.Email_Address).limit(limit).offset(offset) # pagination 
    return [user_out(u) for u in session.scalars(stmt).all()] 

@users_router.get("/SearchUser", response_model=List[UserPublic]) 
@limiter.limit("50/minute") 
def search_user( 
    request: Request, 
    SQRY: Optional[str] = Query(None, description="Search across all fields"), 
    limit: int = Query(50, ge=1, le=500), # pagination 
    offset: int = Query(0, ge=0), # pagination 
    session: Session = Depends(get_session), 
) -> List[UserPublic]: 
    try: 
        stmt = select(User) 
        if SQRY: 
            search_term = f"%{SQRY}%" 
            stmt = stmt.where( 
                or_( 
                    cast(User.Email_Address, String).ilike(search_term), 
                    cast(User.User_Name, String).ilike(search_term), 
                    cast(User.Location_Address, String).ilike(search_term), 
                    cast(User.Contact_Number, String).ilike(search_term), 
                    cast(User.Vat_Number, String).ilike(search_term), 
                    cast(User.Hashed_Pword, String).ilike(search_term), 
                    cast(User.Role, String).ilike(search_term), 
                ) 
            ) 
        stmt = stmt.order_by(User.Email_Address).limit(limit).offset(offset) # pagination 
        results = session.scalars(stmt).all() 
        return [user_out(u) for u in results] 
    except Exception as e: 
        logging.error(f"Search user failed: {e}") 
        raise HTTPException(status_code=500, detail=f"Search user failed: {str(e)}") 

@users_router.post("/CreateUsers", response_model=UserPublic, status_code=201) 
@limiter.limit("50/minute") 
def create_user( 
    request: Request, 
    payload: UserCreate, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["users:manage"])), 
) -> UserPublic: 
    data = payload.model_dump() 
    email = data["Email_Address"].strip().lower() 
    if get_user_by_email(session, email): 
        raise HTTPException(status_code=409, detail="Email already registered") 
    hashed = get_password_hash(data.pop("Password")) 
    u = User( 
        User_Name=data["User_Name"], 
        Location_Address=data.get("Location_Address"), 
        Email_Address=email, 
        Contact_Number=data.get("Contact_Number"), 
        Vat_Number=data.get("Vat_Number"), 
        Hashed_Pword=hashed, 
    ) 
    session.add(u) 
    session.commit() 
    session.refresh(u) 
    return user_out(u) 

@users_router.put("/UpdateUsers/{email}", response_model=UserPublic) 
@limiter.limit("50/minute") 
def update_user( 
    request: Request, 
    email: str, 
    payload: UserUpdate, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["users:manage"])), 
) -> UserPublic: 
    normalized_email = email.strip().lower() 
    u = get_user_by_email(session, normalized_email) 
    if not u: 
        raise HTTPException(status_code=404, detail="User not found") 
    # If Email_Address is provided, normalize & ensure uniqueness 
    if payload.Email_Address is not None: 
        new_email = payload.Email_Address.strip().lower() 
        if new_email != normalized_email: 
            existing = session.scalar( 
                select(User).where(User.Email_Address == new_email, User.User_Id != u.User_Id) 
            ) 
            if existing: 
                raise HTTPException(status_code=409, detail="Email already exists") 
            u.Email_Address = new_email 
    # Update other fields only if provided 
    if payload.User_Name is not None: 
        u.User_Name = payload.User_Name 
    if payload.Location_Address is not None: 
        u.Location_Address = payload.Location_Address 
    if payload.Contact_Number is not None: 
        u.Contact_Number = payload.Contact_Number 
    if payload.Vat_Number is not None: 
        u.Vat_Number = payload.Vat_Number 
    if payload.Is_Active is not None: 
        u.Is_Active = payload.Is_Active 
    if payload.Role is not None: 
        u.Role = payload.Role 
    session.commit() 
    session.refresh(u) 
    return user_out(u) 

@users_router.put("/UpdatePassword/{email}", status_code=204) 
def update_password( 
    email: str, 
    payload: UserPasswordUpdate, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["users:manage"])), 
): 
    u = get_user_by_email(session, email.strip().lower()) 
    if not u: 
        raise HTTPException(status_code=404, detail="User not found") 
    if not verify_password(payload.Old_Password, u.Hashed_Pword): 
        raise HTTPException(status_code=400, detail="Old password incorrect") 
    u.Hashed_Pword = get_password_hash(payload.New_Password) 
    u.TokenVersion = (u.TokenVersion or 1) + 1 # revoke old tokens on password change 
    # Also revoke all refresh tokens for this user
    revoke_all_user_refresh_tokens(session, u)
    session.commit() 
    return Response(status_code=204) 

@users_router.put( 
    "/AssignRole/{email}", 
    status_code=200, 
    dependencies=[Depends(require_role(["admin"]))], 
) 
@limiter.limit("50/minute") 
def assign_role_by_email( 
    request: Request, 
    email: str, 
    new_role: str, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["users:manage"])), 
): 
    u = get_user_by_email(session, email.strip().lower()) 
    if not u: 
        raise HTTPException(status_code=404, detail="User not found") 
    u.Role = new_role 
    session.commit() 
    return {"message": f"Role updated to {new_role} for {email}"} 

@users_router.delete( 
    "/DeleteUsers/{email}", 
    status_code=204, 
    response_class=Response, 
    responses=responses204, 
    dependencies=[Depends(require_role(["admin"]))], 
) 
@limiter.limit("50/minute") 
def delete_user( 
    request: Request, 
    email: str, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["users:manage"])), 
) -> Response: 
    normalized_email = email.strip().lower() 
    u = get_user_by_email(session, normalized_email) 
    if not u: 
        raise HTTPException(status_code=404, detail="User not found") 
    # Revoke refresh tokens before delete
    revoke_all_user_refresh_tokens(session, u)
    session.delete(u) 
    session.commit() 
    return Response(status_code=204) 

@users_router.post( 
    "/RevokeTokens/{email}", 
    status_code=204, 
    dependencies=[Depends(require_role(["admin"]))], 
) 
@limiter.limit("50/minute") 
def revoke_tokens_by_email( 
    request: Request, 
    email: str, 
    session: Session = Depends(get_session), 
    _: User = Depends(require_scopes(["users:manage"])), 
): 
    u = get_user_by_email(session, email.strip().lower()) 
    if not u: 
        raise HTTPException(status_code=404, detail="User not found") 
    u.TokenVersion = (u.TokenVersion or 1) + 1 
    revoke_all_user_refresh_tokens(session, u)
    session.commit() 
    return Response(status_code=204) 

# ------------------------------- AUTH (Public) ------------------------------- 
auth_router = APIRouter(tags=["Authorization"]) 

# Public JWKS endpoint (verifiers use this to fetch public keys) 
@app.get("/.well-known/jwks.json", include_in_schema=False) 
def jwks(): 
    # Cache 5 minutes to reduce verifier load 
    return JSONResponse(rs256_keystore.jwks(), headers={"Cache-Control": "public, max-age=300"}) 

@auth_router.post( 
    "/token", 
    responses={ 
        400: { 
            "description": "Bad credentials", 
            "model": ErrorDetail, 
            "content": { 
                "application/json": { 
                    "example": { 
                        "code": "bad_credentials", 
                        "message": "Invalid username or password.", 
                        "attempts_remaining": 2, 
                    } 
                } 
            }, 
        }, 
        429: { 
            "description": "Too Many Requests (login cooldown active)", 
            "model": ErrorDetail, 
            "content": { 
                "application/json": { 
                    "example": { 
                        "code": "too_many_requests", 
                        "message": "Too many failed login attempts. Try again later.", 
                        "retry_after_seconds": 30, 
                    } 
                } 
            }, 
        }, 
    }, 
) 
@limiter.limit("3/minute") 
def login_for_access_token( 
    request: Request, 
    form_data = Depends(OAuth2PasswordRequestForm), 
    session: Session = Depends(get_session), 
) -> Token:
    ip = request.client.host if request.client else "unknown" 
    email = (form_data.username or "").strip().lower() 
    user = get_user_by_email(session, email) 
    if not user or not verify_password(form_data.password, user.Hashed_Pword): 
        remaining = note_failed_attempt(email, ip) 
        return JSONResponse( 
            status_code=status.HTTP_400_BAD_REQUEST, 
            content=ErrorDetail( 
                code="bad_credentials", 
                message="Invalid username or password.", 
                attempts_remaining=remaining, 
            ).model_dump(), 
        ) 
    if not user.Is_Active: 
        remaining = get_attempts_remaining(email, ip) 
        return JSONResponse( 
            status_code=status.HTTP_400_BAD_REQUEST, 
            content=ErrorDetail( 
                code="inactive_user", 
                message="Inactive user.", 
                attempts_remaining=remaining, 
            ).model_dump(), 
        ) 
    clear_attempts(email, ip) 
    # If user's hash uses a deprecated scheme (e.g., bcrypt), rehash to argon2 
    try: 
        if pwd_context.needs_update(user.Hashed_Pword): 
            user.Hashed_Pword = get_password_hash(form_data.password) 
            session.commit() 
    except Exception: 
        pass 
    scopes = ROLE_TO_SCOPES.get(user.Role or "user", []) 
    access_token = create_access_token( 
        data={"sub": user.Email_Address, "ver": user.TokenVersion, "scopes": scopes} 
    ) 

    # NEW: Issue refresh token (rotate any existing)
    refresh_token_raw = issue_refresh_token(session, user)
    resp_body = Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token_raw, expires_in=TOKEN_EXPIRES_MIN * 60)

    # Optional cookie delivery
    if REFRESH_IN_COOKIE:
        response = JSONResponse(content=resp_body.model_dump())
        response.set_cookie(
            key=REFRESH_COOKIE_NAME,
            value=refresh_token_raw,
            httponly=True,
            secure=REFRESH_COOKIE_SECURE,
            samesite=REFRESH_COOKIE_SAMESITE,
            max_age=REFRESH_EXPIRES_DAYS * 24 * 3600,
            path="/",
        )
        return response

    return resp_body 

@auth_router.get("/me", response_model=UserPublic, summary="Identify me! (Requires Bearer token)") 
def read_me(current_user: User = Depends(get_current_user)) -> UserPublic: 
    """Quick way to test your token.""" 
    return user_out(current_user) 

@auth_router.post("/Register", response_model=UserPublic, status_code=201, summary="Register User") 
def register_user(payload: UserCreate, session: Session = Depends(get_session)) -> UserPublic: 
    email = payload.Email_Address.strip().lower() 
    if get_user_by_email(session, email): 
        raise HTTPException(status_code=409, detail="Email already registered") 
    hashed = get_password_hash(payload.Password) 
    u = User( 
        User_Name=payload.User_Name, 
        Location_Address=payload.Location_Address, 
        Email_Address=email, 
        Contact_Number=payload.Contact_Number, 
        Vat_Number=payload.Vat_Number, 
        Hashed_Pword=hashed, 
    ) 
    session.add(u) 
    session.commit() 
    session.refresh(u) 
    return user_out(u) 

# NEW: Refresh endpoint (rotation + reuse detection)
class RefreshRequest(BaseModel):
    refresh_token: str

@auth_router.post("/token/refresh")
@limiter.limit("20/minute")
def refresh_access_token(
    request: Request,
    payload: RefreshRequest,
    session: Session = Depends(get_session)
) -> Token:
    raw = (payload.refresh_token or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Missing refresh_token")

    fp = _fp_sha256(raw)
    rec = find_refresh_record_by_fp(session, fp)
    if not rec:
        # Unknown token: generic failure
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Load user
    user = session.get(User, rec.User_Id)
    if not user or not user.Is_Active:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    now = _now_utc()
    # Reuse detection: if revoked or expired, consider compromised → bump TokenVersion and purge refresh tokens
    if rec.Is_Revoked or rec.Expires_At <= now:
        user.TokenVersion = (user.TokenVersion or 1) + 1
        revoke_all_user_refresh_tokens(session, user)
        session.commit()
        raise HTTPException(status_code=401, detail="Refresh token reuse detected; tokens revoked")

    # Verify hash
    try:
        if not pwd_context.verify(raw, rec.Token_Hash):
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # TokenVersion mismatch? credentials revoked → deny and clean up
    if int(rec.TokenVersionAtIssue or 1) != int(user.TokenVersion or 1):
        revoke_all_user_refresh_tokens(session, user)
        raise HTTPException(status_code=401, detail="Refresh token revoked")

    # ROTATE: revoke the current refresh record and issue a fresh one
    rec.Is_Revoked = True
    session.commit()

    scopes = ROLE_TO_SCOPES.get(user.Role or "user", [])
    new_access = create_access_token(data={"sub": user.Email_Address, "ver": user.TokenVersion, "scopes": scopes})
    new_refresh = issue_refresh_token(session, user)

    body = Token(access_token=new_access, token_type="bearer", refresh_token=new_refresh, expires_in=TOKEN_EXPIRES_MIN * 60)

    if REFRESH_IN_COOKIE:
        response = JSONResponse(content=body.model_dump())
        response.set_cookie(
            key=REFRESH_COOKIE_NAME,
            value=new_refresh,
            httponly=True,
            secure=REFRESH_COOKIE_SECURE,
            samesite=REFRESH_COOKIE_SAMESITE,
            max_age=REFRESH_EXPIRES_DAYS * 24 * 3600,
            path="/",
        )
        return response

    return body

# NEW: Logout endpoint (revokes provided refresh token)
class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None

@auth_router.post("/logout", status_code=204)
def logout(payload: LogoutRequest | None = None, request: Request = None, session: Session = Depends(get_session)):
    raw = None
    if REFRESH_IN_COOKIE and request is not None:
        raw = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw and payload and payload.refresh_token:
        raw = payload.refresh_token.strip()
    if not raw:
        return Response(status_code=204)  # nothing to do

    fp = _fp_sha256(raw)
    rec = find_refresh_record_by_fp(session, fp)
    if rec:
        rec.Is_Revoked = True
        session.commit()
    return Response(status_code=204)

# ============================ Health Check ================================== 
@app.get("/healthz", include_in_schema=False) 
def healthz(session: Session = Depends(get_session)):
    """ 
    Simple liveness/readiness check: 
    - returns 200 and {"status":"ok"} if DB responds to SELECT 1 
    - returns 503 if DB is unreachable 
    """ 
    try: 
        session.execute(select(1)) 
        return {"status": "ok"} 
    except Exception as e: 
        return JSONResponse(status_code=503, content={"status": "degraded", "error": str(e)}) 


# ============================ Okta OIDC (PKCE + JWKS) ==========================
import json, secrets, base64, hashlib
from typing import Optional, Dict
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, BigInteger
from sqlalchemy import create_engine as create_engine_okta
from sqlalchemy.orm import sessionmaker as sessionmaker_okta
from jose import jwt  # python-jose


# --- replace these lines in your Okta config block ---
OKTA_ISSUER = (os.getenv("OKTA_ISSUER") or "").strip()
OKTA_METADATA_URL = (os.getenv("OKTA_METADATA_URL") or "").strip()
OKTA_CLIENT_ID = (os.getenv("OKTA_CLIENT_ID") or "").strip()
OKTA_CLIENT_SECRET = (os.getenv("OKTA_CLIENT_SECRET") or "").strip()
OKTA_REDIRECT_URI = (os.getenv("OKTA_REDIRECT_URI") or "").strip()
OKTA_DEFAULT_SCOPES = (os.getenv("OKTA_DEFAULT_SCOPES", "openid profile email offline_access")).strip()

if not all([OKTA_ISSUER, OKTA_METADATA_URL, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET, OKTA_REDIRECT_URI]):
    logging.warning("Okta env incomplete; /authorize and /callback will fail.")

okta_router = APIRouter(tags=["Okta"])

# --- PKCE state store (SQLite) ---
PKCE_DB_URL = os.getenv("PKCE_DB_URL", "sqlite:///./pkce_state.db")
STATE_TTL_SEC = int(os.getenv("PKCE_STATE_TTL_SEC", "600"))  # 10 minutes

BasePKCE = declarative_base()
engine_pkce = create_engine_okta(PKCE_DB_URL, connect_args={"check_same_thread": False})
BasePKCE.metadata.create_all(bind=engine_pkce)
SessionPKCE = sessionmaker_okta(bind=engine_pkce, autocommit=False, autoflush=False)

class PKCEState(BasePKCE):
    __tablename__ = "pkce_state"
    state = Column(String, primary_key=True, index=True)
    code_verifier = Column(String, nullable=False)
    nonce = Column(String, nullable=False)
    created_at = Column(BigInteger, nullable=False)

BasePKCE.metadata.create_all(bind=engine_pkce)

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
            db.delete(rec); db.commit()
            return None
        out = {"code_verifier": rec.code_verifier, "nonce": rec.nonce}
        db.delete(rec); db.commit()  # one-time use
        return out

# --- OIDC metadata & JWKS cache ---
_oidc_meta: Optional[Dict] = None
_jwks: Optional[Dict] = None
_jwks_exp = 0

async def get_oidc_metadata() -> Dict:
    global _oidc_meta
    if _oidc_meta:
        return _oidc_meta
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(OKTA_METADATA_URL)
        r.raise_for_status()
        _oidc_meta = r.json()
        return _oidc_meta

async def get_jwks() -> Dict:
    global _jwks, _jwks_exp
    now = int(time.time())
    if _jwks and now < _jwks_exp:
        return _jwks
    meta = await get_oidc_metadata()
    jwks_uri = meta.get("jwks_uri")
    if not jwks_uri:
        raise HTTPException(status_code=500, detail="jwks_uri missing in metadata")
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(jwks_uri)
        r.raise_for_status()
        _jwks = r.json()
        _jwks_exp = now + 600  # 10 min cache
        return _jwks

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _sha256_b64(s: str) -> str:
    return _b64url(hashlib.sha256(s.encode("ascii")).digest())

def _build_authz_url(auth_endpoint: str, state: str, code_challenge: str, nonce: str) -> str:
    from urllib.parse import urlencode
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
    return f"{auth_endpoint}?{urlencode(params)}"

def _select_jwk_by_kid(jwks: Dict, kid: str) -> Optional[Dict]:
    for k in jwks.get("keys", []):
        if k.get("kid") == kid and k.get("kty") == "RSA":
            return k
    return None



@okta_router.get("/authorize")
async def okta_authorize():
    try:
        meta = await get_oidc_metadata()
        auth_endpoint = meta.get("authorization_endpoint")
        if not auth_endpoint:
            logging.error("Okta metadata missing authorization_endpoint")
            raise HTTPException(status_code=500, detail="authorization_endpoint missing")

        code_verifier = secrets.token_urlsafe(64)
        code_challenge = _sha256_b64(code_verifier)
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)

        logging.info("PKCE pre-save: state=%s, nonce=%s", state, nonce)
        save_pkce_state(state, code_verifier, nonce)
        logging.info("PKCE saved OK")

        url = _build_authz_url(auth_endpoint, state, code_challenge, nonce)
        logging.info("Okta /authorize → %s", url)
        return RedirectResponse(url, status_code=302)
    except Exception as ex:
        logging.exception("Authorize failed: %s", ex)
        raise HTTPException(status_code=400, detail=str(ex))

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

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OKTA_REDIRECT_URI,
        "client_id": OKTA_CLIENT_ID,
        "code_verifier": code_verifier,
        "client_secret": OKTA_CLIENT_SECRET,
    }
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(token_endpoint, data=data)
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text}")
        tokens = resp.json()

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="ID token missing")

    # Verify ID token via JWKS (RS256, iss, aud, exp, nonce)
    jwks = await get_jwks()
    header = jwt.get_unverified_header(id_token)
    kid = header.get("kid")
    alg = header.get("alg")
    if alg != "RS256":
        raise HTTPException(status_code=400, detail=f"Unsupported alg {alg}, expected RS256")
    jwk = _select_jwk_by_kid(jwks, kid)
    if not jwk:
        raise HTTPException(status_code=400, detail="Matching JWK not found for kid")

    try:
        claims = jwt.decode(
            id_token,
            jwk,  # python-jose accepts JWK dict
            algorithms=["RS256"],
            audience=OKTA_CLIENT_ID,
            issuer=OKTA_ISSUER,
            options={"require_exp": True, "require_iat": True, "require_aud": True, "require_iss": True},
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"ID token verification failed: {str(e)}")

    if claims.get("nonce") != expected_nonce:
        raise HTTPException(status_code=400, detail="Nonce mismatch")

    # Success: return tokens + claims
    return JSONResponse({
        "ok": True,
        "provider": "okta",
        "id_token_claims": claims,
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "token_type": tokens.get("token_type"),
        "expires_in": tokens.get("expires_in"),
    })

@okta_router.get("/authz/ready", include_in_schema=False)
async def okta_authz_ready():
    issues = []
    for k, v in [("OKTA_ISSUER", OKTA_ISSUER), ("OKTA_METADATA_URL", OKTA_METADATA_URL), ("OKTA_CLIENT_ID", OKTA_CLIENT_ID), ("OKTA_CLIENT_SECRET", "***" if OKTA_CLIENT_SECRET else None), ("OKTA_REDIRECT_URI", OKTA_REDIRECT_URI)]:
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

# ============================ Mount Routers ================================== 
require_client_auth = os.getenv("REQUIRE_CLIENT_AUTH", "true").lower() == "true" 
protected = [Depends(get_current_user), Depends(set_rate_limit_identity)] if require_client_auth else [] 
app.include_router(orders_router, dependencies=protected) 
app.include_router(customers_router, dependencies=protected) 
app.include_router(invoices_router, dependencies=protected) 
app.include_router(agreements_router, dependencies=protected) 
app.include_router(users_router, dependencies=protected) 
app.include_router(auth_router)
app.include_router(okta_router) 

@app.get("/docs-custom", include_in_schema=False) 
def custom_docs(): 
    file_path = STATIC_DIR / "swagger-custom.html" 
    if not file_path.exists(): 
        return HTMLResponse(content="<h1>swagger-custom.html not found in static folder</h1>", status_code=404) 
    html_content = file_path.read_text(encoding="utf-8") 
    return HTMLResponse(content=html_content) 

