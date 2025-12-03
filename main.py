# SimpleAPI_SQLAlchemy_version.py
"""
API - SQLAlchemy + OAuth2/JWT (Beginner-friendly)

What this version adds:
  1) All endpoints are LOCKED by default.
  2) They UNLOCK only when you log in and pass a valid Bearer token.
  3) OAuth2 Password Flow with JWT access tokens.
  4) Token expires in 30 minutes (configurable).
  5) POST /Register  : Register a new user (public).
  6) POST /token     : Login to get an access token (public).
  7) GET  /me        : Example protected endpoint for quick testing.

Run locally:
  uvicorn SimpleAPI_SQLAlchemy_version:app --reload --port 8001
"""
from __future__ import annotations

import os

from dotenv import load_dotenv  # pip install python-dotenv
from sqlalchemy.orm import Session

from fastapi import FastAPI, Request


from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

app = FastAPI()

# Mount static folder
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/docs-custom", response_class=HTMLResponse)
async def custom_docs():
    with open("templates/swagger-custom.html") as f:
        return f.read()


from datetime import datetime, timedelta, timezone
from typing import Iterator, List, Optional, Union

from pathlib import Path
from fastapi.staticfiles import StaticFiles

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import Response
import logging
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, Integer, String, create_engine 
from sqlalchemy import select, or_, cast
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
# --- Security imports (OAuth2 + JWT + password hashing) ---
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt  # pip install "python-jose[cryptography]"


# Map role to scopes
ROLE_TO_SCOPES = {
    "admin": ["orders:read", "orders:write", "agreements:read", "agreements:write", "users:manage"],
    "manager": ["orders:read", "orders:write", "agreements:read"],
    "viewer": ["orders:read", "agreements:read"],
    "user": ["orders:read"]
}

# ============================ Security Config ================================
# For study/demo purposes only—use environment variables in production!
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
TOKEN_EXPIRES_MIN = int(os.getenv("TOKEN_EXPIRES_MIN", "60"))

# Password hashing context (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Tell FastAPI where the token endpoint lives (for Swagger's "Authorize" button)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# ============================ App & CORS (dev-open) ==========================
app = FastAPI(title="Bugzy API Development - FastAPI/SQLAlchemy/Pydantic/Alembic + PostgreSQL, OAuth2, Passlib, Token Revocation/Expiration/Versioning, Role Assignment - Swagger UI")

# After app = FastAPI(...)

# Load environment variables from .env (dev convenience)
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

raw_origins = os.getenv("CORS_ORIGINS", "")
allow_origins: List[str] = [o.strip() for o in raw_origins.split(",") if o.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ============================ Database (PostgreSQL) ==========================
DATABASE_URL = os.getenv("DB_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError("DB_URL is not set. Put it in .env or environment variables.")

# For psycopg2 + PostgreSQL. Neon requires SSL; it's already in the URL.
engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,   # helps recover stale connections
)

class Base(DeclarativeBase):
    """Base class for ORM models."""

# ---------------------------- ORM MODELS SQLALCHEMY-------------------------------------
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
    Email_Address: Mapped[EmailStr] = mapped_column(String(50), nullable=True)

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
    
# Create tables if missing (note: does not ALTER existing tables)
# Base.metadata.create_all(engine)

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

# Users (separate Create vs Public to avoid exposing passwords)
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
        
    class Config:
        orm_mode = True

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

class TokenData(BaseModel):
    email: Optional[str] = None

# -----------------------------------------------------------------------------
# Swagger UI (dark, with no-dim text/labels) swagger-dark.css in static folder
# -----------------------------------------------------------------------------
@app.get("/docs-dark", include_in_schema=False)
def docs_dark():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Docs (Dark)",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-dark.css?v=24",  # bump v to bust cache
        swagger_favicon_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/favicon-32x32.png",
    )

# ====================== AUTH HELPERS (hash, verify, JWT) =====================
def get_password_hash(password: str) -> str:
    """Return a bcrypt hash for secure storage."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plaintext password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_minutes: int = TOKEN_EXPIRES_MIN) -> str:
    """Create a signed JWT with an expiry (exp) claim."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(session: Session, email: str) -> Optional[User]:
    return session.scalar(select(User).where(User.Email_Address == email))


def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    """
    Decode and validate the Bearer token, fetch the user, ensure they are active.
    If anything fails -> 401 Unauthorized.
    """
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials (invalid or expired token)",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        token_ver = payload.get("ver")
        scopes = payload.get("scopes", [])  # Extract scopes from JWT

        if email is None or token_ver is None:
            raise credentials_error

        user = get_user_by_email(session, email)
        if user is None or not user.Is_Active:
            raise credentials_error

        # Check token version for revocation
        if token_ver != user.TokenVersion:
            raise HTTPException(status_code=401, detail="Token revoked")

        # Attach scopes to user object for convenience
        user.Scopes = scopes

        return user

    except JWTError:
        raise credentials_error
    except Exception as e:
        logging.error(f"Token validation failed: {e}")
        raise credentials_error

def require_role(allowed_roles: list[str]):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.Role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker

# ================================ ROUTERS ====================================
# orders
orders_router = APIRouter(tags=["Orders"])

@orders_router.get("/GetOrder/{Order_Number}", response_model=OrderOut)
def get_order(Order_Number: int, session: Session = Depends(get_session)) -> OrderOut:
    o = session.get(Order, Order_Number)
    if not o:
        raise HTTPException(status_code=404, detail="Order not found")
    return order_out(o)

@orders_router.get("/Listorders", response_model=List[OrderOut])
def list_orders(
    Order_Number: Optional[int] = None,
    session: Session = Depends(get_session),
) -> List[OrderOut]:
    stmt = select(Order)
    if Order_Number is not None:
        stmt = stmt.where(Order.Order_Number == Order_Number)
    stmt = stmt.order_by(Order.Order_Number)
    return [order_out(o) for o in session.scalars(stmt).all()]

@orders_router.get("/SearchOrder", response_model=List[OrderOut])
def search_order(
    SQRY: Optional[str] = Query(None, description="Search across all fields"),
    session: Session = Depends(get_session)
) -> List[OrderOut]:
    try:
        stmt = select(Order)

        if SQRY:
            search_term = f"%{SQRY}%"
            stmt = stmt.where(or_(
                cast(Order.Order_Number, String).ilike(search_term),
                cast(Order.Customer_Number, String).ilike(search_term),
                cast(Order.Quantity, String).ilike(search_term),
                cast(Order.Price, String).ilike(search_term)  
            ))

        stmt = stmt.order_by(Order.Order_Number)
        results = session.scalars(stmt).all()
        return [order_out(o) for o in results]

    except Exception as e:
        logging.error(f"Search order failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search order failed: {str(e)}")

@orders_router.post("/Createorders", response_model=List[OrderOut], status_code=201)
def create_orders(payload: List[OrderIn], session: Session = Depends(get_session)):
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
        import logging
        logging.exception("Create order failed")
        raise HTTPException(status_code=500, detail=f"Create order failed: {e}")
    for o in created:
        session.refresh(o)
    return [order_out(o) for o in created]

@orders_router.put("/Updateorders/{Order_Number}", response_model=OrderOut)
def update_order(
    Order_Number: int, payload: OrderIn, session: Session = Depends(get_session)
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

@orders_router.delete("/Deleteorders/{Order_Number}", status_code=204)
def delete_order(Order_Number: int, session: Session = Depends(get_session)) -> Response:
    o = session.get(Order, Order_Number)
    if not o:
        raise HTTPException(status_code=404, detail="Order not found")
    session.delete(o)
    session.commit()
    return Response(status_code=204)

# customers
customers_router = APIRouter(tags=["Customers"])

@customers_router.get("/GetCustomer/{Customer_Number}", response_model=CustomerOut)
def get_customer(
    Customer_Number: int, session: Session = Depends(get_session)
) -> CustomerOut:
    c = session.get(Customer, Customer_Number)
    if not c:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer_out(c)

@customers_router.get("/Listcustomers", response_model=List[CustomerOut])
def list_customers(
    Customer_Number: Optional[int] = None, session: Session = Depends(get_session)
) -> List[CustomerOut]:
    stmt = select(Customer)
    if Customer_Number is not None:
        stmt = stmt.where(Customer.Customer_Number == Customer_Number)
    stmt = stmt.order_by(Customer.Customer_Number)
    return [customer_out(c) for c in session.scalars(stmt).all()]


@customers_router.get("/SearchCustomer", response_model=List[CustomerOut])
def search_customer(
    SQRY: Optional[str] = Query(None, description="Search across all fields"),
    session: Session = Depends(get_session)
) -> List[CustomerOut]:
    try:
        stmt = select(Customer)

        if SQRY:
            search_term = f"%{SQRY}%"
            stmt = stmt.where(or_(
                cast(Customer.Customer_Number, String).ilike(search_term),
                cast(Customer.Customer_Name, String).ilike(search_term),
                cast(Customer.Customer_Address, String).ilike(search_term),
                cast(Customer.Contact_Number, String).ilike(search_term),
                cast(Customer.Email_Address, String).ilike(search_term)                
            ))

        stmt = stmt.order_by(Customer.Customer_Number)
        results = session.scalars(stmt).all()
        return [customer_out(c) for c in results]

    except Exception as e:
        logging.error(f"Search customer failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search customer failed: {str(e)}") 

from sqlalchemy.exc import IntegrityError
import logging

@customers_router.post("/Createcustomers", response_model=List[CustomerOut], status_code=201)
def create_customer(payload: List[CustomerIn], session: Session = Depends(get_session)):
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
        import logging
        logging.exception("Create customer  failed")
        raise HTTPException(status_code=500, detail=f"Create customer failed: {e}")
    for c in created:
        session.refresh(c)
    return [customer_out(c) for c in created]

@customers_router.put("/Updatecustomers/{Customer_Number}", response_model=CustomerOut)
def update_customer(
    Customer_Number: int, payload: CustomerIn, session: Session = Depends(get_session)
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

@customers_router.delete("/Deletecustomers/{Customer_Number}", status_code=204)
def delete_customer(
    Customer_Number: int, session: Session = Depends(get_session)
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
def get_invoice(
    Invoice_Number: int, session: Session = Depends(get_session)
) -> InvoiceOut:
    i = session.get(Invoice, Invoice_Number)
    if not i:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice_out(i)

@invoices_router.get("/Listinvoices", response_model=List[InvoiceOut])
def list_invoices(
    invoice_number: Optional[int] = None, session: Session = Depends(get_session)
) -> List[InvoiceOut]:
    stmt = select(Invoice)
    if invoice_number is not None:
        stmt = stmt.where(Invoice.Invoice_Number == invoice_number)
    stmt = stmt.order_by(Invoice.Invoice_Number)
    return [invoice_out(i) for i in session.scalars(stmt).all()]

@invoices_router.get("/SearchInvoice", response_model=List[InvoiceOut])
def search_invoice(
    SQRY: Optional[str] = Query(None, description="Search across all fields"),
    session: Session = Depends(get_session)
) -> List[InvoiceOut]:
    try:
        stmt = select(Invoice)

        if SQRY:
            search_term = f"%{SQRY}%"
            stmt = stmt.where(or_(
                cast(Invoice.Invoice_Number, String).ilike(search_term),
                cast(Invoice.Customer_Number, String).ilike(search_term),
                cast(Invoice.Order_Number, String).ilike(search_term),
                cast(Invoice.Invoice_Date, String).ilike(search_term),
                cast(Invoice.Invoice_Email, String).ilike(search_term),
                cast(Invoice.Amount, String).ilike(search_term)  
            ))

        stmt = stmt.order_by(Invoice.Invoice_Number)
        results = session.scalars(stmt).all()
        return [invoice_out(i) for i in results]

    except Exception as e:
        logging.error(f"Search invoice failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search invoice failed: {str(e)}")

@invoices_router.post("/Createinvoices", response_model=List[InvoiceOut], status_code=201)
def create_invoices(payload: List[InvoiceIn], session: Session = Depends(get_session)):
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
        import logging
        logging.exception("Create invoice failed")
        raise HTTPException(status_code=500, detail=f"Create invoice failed: {e}")
    for i in created:
        session.refresh(i)
    return [invoice_out(i) for i in created]

@invoices_router.put("/Updateinvoices/{Invoice_Number}", response_model=InvoiceOut)
def update_invoice(
    Invoice_Number: int, payload: InvoiceIn, session: Session = Depends(get_session)
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

@invoices_router.delete("/Deleteinvoices/{Invoice_Number}", status_code=204)
def delete_invoice(
    Invoice_Number: int, session: Session = Depends(get_session)
) -> Response:
    i = session.get(Invoice, Invoice_Number)
    if not i:
        raise HTTPException(status_code=404, detail="Invoice not found")
    session.delete(i)
    session.commit()
    return Response(status_code=204)

# agreements (basic listing/getting kept for study; still protected)

agreements_router = APIRouter(tags=["Agreements"])

@agreements_router.get("/GetAgreement/{Agreement_number}", response_model=AgreementOut)
def get_agreement(
    Agreement_number: str, session: Session = Depends(get_session)
) -> AgreementOut:
    a = session.get(Agreement, Agreement_number)
    if not a:
        raise HTTPException(status_code=404, detail="Agreement not found")
    return agreement_out(a)

@agreements_router.get("/Listagreements", response_model=List[AgreementOut])
def list_agreements(
    Agreement_number: Optional[str] = None, session: Session = Depends(get_session)
) -> List[AgreementOut]:
    stmt = select(Agreement)
    if Agreement_number is not None:
        stmt = stmt.where(Agreement.Agreement_number == Agreement_number)
    stmt = stmt.order_by(Agreement.Agreement_number)
    return [agreement_out(a) for a in session.scalars(stmt).all()]

@agreements_router.get("/Searchagreements", response_model=List[AgreementOut])
def search_agreements(
    SQRY: Optional[str] = Query(None, description="Search across all fields"),
    session: Session = Depends(get_session)
) -> List[AgreementOut]:
    try:
        stmt = select(Agreement)

        if SQRY:
            search_term = f"%{SQRY}%"
            stmt = stmt.where(or_(
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
                Agreement.Project_number.ilike(search_term)
            ))

        stmt = stmt.order_by(Agreement.Agreement_number)
        results = session.scalars(stmt).all()
        return [agreement_out(a) for a in results]

    except Exception as e:
        logging.error(f"Search agreement failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search agreement failed: {str(e)}")

@agreements_router.post("/Createagreements", response_model=List[AgreementOut], status_code=201)
def create_agreement(payload: List[AgreementIn], session: Session = Depends(get_session)):
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
        import logging
        logging.exception("Create order failed")
        raise HTTPException(status_code=500, detail=f"Agreement create failed: {e}")
    for a in created:
        session.refresh(a)
    return [agreement_out(a) for a in created]

@agreements_router.put("/Updateagreements/{Agreement_number}", response_model=AgreementOut)
def update_agreement(
    Agreement_number: str, payload: AgreementIn, session: Session = Depends(get_session)
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


@agreements_router.delete("/DeleteAgreement/{Agreement_number}", status_code=204)
def delete_agreement(Agreement_number: str, session: Session = Depends(get_session)) -> Response:
    a = session.get(Agreement, Agreement_number)
    if not a:
        raise HTTPException(status_code=404, detail="Agreement not found")
    session.delete(a)
    session.commit()
    return Response(status_code=204)

# Users (basic listing/getting kept for study; still protected)
users_router = APIRouter(tags=["Users"])

@users_router.get("/GetUser/{email}", response_model=UserPublic)
def get_user(email: str, session: Session = Depends(get_session)) -> UserPublic:
    normalized_email = email.strip().lower()
    u = session.scalar(select(User).where(User.Email_Address == normalized_email))
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return user_out(u)


@users_router.get("/ListUsers", response_model=List[UserPublic])
def list_users(
    email: Optional[str] = None, session: Session = Depends(get_session)
) -> List[UserPublic]:
    stmt = select(User)
    if email:
        stmt = stmt.where(User.Email_Address == email.strip().lower())
    stmt = stmt.order_by(User.Email_Address)
    return [user_out(u) for u in session.scalars(stmt).all()]


@users_router.get("/SearchUser", response_model=List[UserPublic])
def search_user(
    SQRY: Optional[str] = Query(None, description="Search across all fields"),
    session: Session = Depends(get_session)
) -> List[UserPublic]:
    try:
        stmt = select(User)
        if SQRY:
            search_term = f"%{SQRY}%"
            stmt = stmt.where(or_(
                cast(User.Email_Address, String).ilike(search_term),
                cast(User.User_Name, String).ilike(search_term),
                cast(User.Location_Address, String).ilike(search_term),
                cast(User.Contact_Number, String).ilike(search_term),
                cast(User.Vat_Number, String).ilike(search_term),
                cast(User.Hashed_Pword, String).ilike(search_term),
                cast(User.Role, String).ilike(search_term)                
            ))
        stmt = stmt.order_by(User.Email_Address)
        results = session.scalars(stmt).all()
        return [user_out(u) for u in results]
    except Exception as e:
        logging.error(f"Search user failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search user failed: {str(e)}")

# (Kept for parity) Create/Update/Delete users via admin operations
@users_router.post("/CreateUsers", response_model=UserPublic, status_code=201)
def create_user(payload: UserCreate, session: Session = Depends(get_session)) -> UserPublic:
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
def update_user(
    email: str, payload: UserCreate, session: Session = Depends(get_session)
) -> UserPublic:
    normalized_email = email.strip().lower()
    u = get_user_by_email(session, normalized_email)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    new_email = payload.Email_Address.strip().lower()

    # If changing email, ensure uniqueness against other users
    if new_email != normalized_email:
        existing = session.scalar(
            select(User).where(
                User.Email_Address == new_email,
                User.User_Id != u.User_Id
            )
        )
        if existing:
            raise HTTPException(status_code=409, detail="Email already exists")

    u.User_Name = payload.User_Name
    u.Location_Address = payload.Location_Address
    u.Email_Address = new_email
    u.Contact_Number = payload.Contact_Number
    u.Vat_Number = payload.Vat_Number
    # Optional: allow password change
    # u.Hashed_Pword = get_password_hash(payload.Password)

    session.commit()
    session.refresh(u)
    return user_out(u)

@users_router.put("/AssignRole/{email}", status_code=200, dependencies=[Depends(require_role(["admin"]))])
def assign_role_by_email(email: str, new_role: str, session: Session = Depends(get_session)):
    u = get_user_by_email(session, email.strip().lower())
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u.Role = new_role
    session.commit()
    return {"message": f"Role updated to {new_role} for {email}"}


@users_router.delete("/DeleteUsers/{email}", status_code=204, dependencies=[Depends(require_role(["admin"]))])
def delete_user(email: str, session: Session = Depends(get_session)) -> Response:
    normalized_email = email.strip().lower()
    u = get_user_by_email(session, normalized_email)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(u)
    session.commit()
    return Response(status_code=204)

@users_router.post("/RevokeTokens/{email}", status_code=204, dependencies=[Depends(require_role(["admin"]))])
def revoke_tokens_by_email(email: str, session: Session = Depends(get_session)):
    u = get_user_by_email(session, email.strip().lower())
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u.TokenVersion = (u.TokenVersion or 1) + 1
    session.commit()
    return Response(status_code=204)

# ----------------------------- AUTH (Public) ---------------------------------
auth_router = APIRouter(tags=["Authorization"])

@auth_router.post("/Register", response_model=UserPublic, status_code=201, summary="Register User")
def register_user(payload: UserCreate, session: Session = Depends(get_session)) -> UserPublic:
    """
    Create a new user. Stores only the hashed password (bcrypt).
    This endpoint is PUBLIC so first-time users can sign up.
    """
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

@auth_router.post("/token", response_model=Token, summary="Login for Access Token")
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
) -> Token:
    email = form_data.username.strip().lower()
    user = get_user_by_email(session, email)
    if not user or not verify_password(form_data.password, user.Hashed_Pword):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if not user.Is_Active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    ROLE_TO_SCOPES = {
        "admin": ["orders:read", "orders:write", "customers:read", "customers:write", "invoices:read", "invoices:write", "agreements:read", "agreements:write", "users:manage"],
        "manager": ["orders:read", "orders:write", "customers:read", "customers:write", "invoices:read", "invoices:write", "agreements:read", "agreements:write"],
        "viewer": ["orders:read", "customers:read", "invoices:read", "agreements:read"],
    }

    scopes = ROLE_TO_SCOPES.get(user.Role or "user", [])

    access_token = create_access_token(data={
        "sub": user.Email_Address,
        "ver": user.TokenVersion,
        "scopes": scopes
    })

    return Token(access_token=access_token, token_type="bearer")

@auth_router.get("/me", response_model=UserPublic, summary="Identify me! (Requires Bearer token)")
def read_me(current_user: User = Depends(get_current_user)) -> UserPublic:
    """Quick way to test your token."""
    return user_out(current_user)

# ============================ Mount Routers ==================================
# IMPORTANT: this is how we LOCK everything by default.
# We add a global dependency to each "business" router so that every endpoint
# requires a valid Bearer token. The auth router stays PUBLIC.
require_auth = os.getenv("REQUIRE_CLIENT_AUTH", "true").lower() == "true"
protected = [Depends(get_current_user)] if require_auth else []

# Protected (or open if require_auth=False)
app.include_router(orders_router, dependencies=protected)
app.include_router(customers_router, dependencies=protected)
app.include_router(invoices_router, dependencies=protected)
app.include_router(agreements_router, dependencies=protected)
app.include_router(users_router, dependencies=protected)

# Auth is always public
app.include_router(auth_router)


from fastapi.responses import HTMLResponse

@app.get("/docs-custom", include_in_schema=False)
def custom_docs():
    file_path = STATIC_DIR / "swagger-custom.html"
    if not file_path.exists():
        return HTMLResponse(content="<h1>swagger-custom.html not found in static folder</h1>", status_code=404)
    html_content = file_path.read_text(encoding="utf-8")
    return HTMLResponse(content=html_content)

# ================================ Entrypoint =================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)