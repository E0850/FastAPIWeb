import os
import re
import html
from datetime import datetime, timedelta
from decimal import Decimal
from typing import List, Optional, Dict, Any, Tuple

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Query,
    Path,
    status,
    Security,
    Form,
)
from fastapi.security import (
    OAuth2PasswordBearer,
    SecurityScopes,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    Column,
    Integer,
    SmallInteger,
    String,
    Numeric,
    DateTime,
    Boolean,
    select,
    insert,
    update,
    delete,
    text, Float,  Text)
from sqlalchemy.orm import sessionmaker, Session

# Auto-load .env for local/dev runs (safe no-op in prod)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ------------------------------------------------------------------------------------
# FastAPI App
# ------------------------------------------------------------------------------------
app = FastAPI(title="Fernando Test API Development")

# CORS (configure via env CORS_ORIGINS="*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------------
# Database
# ------------------------------------------------------------------------------------
# --------------------------------------------------------
# Database (Render-friendly env vars + scheme normalization)
# --------------------------------------------------------
import os, html
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def _resolve_db_url() -> str:
    raw = (
        os.getenv('DB_URL')
        or os.getenv('DATABASE_URL')
        or os.getenv('DATABASE_INTERNAL_URL')
        or ''
    ).strip()

    if not raw:
        raise RuntimeError('DB_URL is required (no hardcoded defaults). Set DB_URL or DATABASE_URL or DATABASE_INTERNAL_URL.')

    raw = html.unescape(raw)

    if raw.startswith('postgres://'):
        raw = raw.replace('postgres://', 'postgresql+psycopg2://', 1)

    return raw

DB_URL = _resolve_db_url()
engine = create_engine(DB_URL, future=True, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
metadata = MetaData()

# ------------------------------------------------------------------------------------
# OAuth2 / JWT configuration
# ------------------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is required.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# ------------------------------------------------------------------------------------
# Token Revocation Logic (in-memory per-token + token_version in DB)
# ------------------------------------------------------------------------------------
revoked_tokens: Dict[str, datetime] = {}

def _cleanup_revoked_tokens(now: Optional[datetime] = None) -> None:
    now = now or datetime.utcnow()
    expired = [tok for tok, exp in revoked_tokens.items() if exp <= now]
    for tok in expired:
        revoked_tokens.pop(tok, None)

def revoke_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if exp:
            revoked_tokens[token] = datetime.utcfromtimestamp(exp)
    except Exception:
        pass

def is_token_revoked(token: str) -> bool:
    _cleanup_revoked_tokens()
    return token in revoked_tokens

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SCOPES: Dict[str, str] = {
    "items:read": "Read items",
    "items:write": "Create/update/delete items",
    "extras:read": "Read extras",
    "extras:write": "Create/update/delete extras",
    "cars:read": "Read car_control",
    "cars:write": "Create/update/delete car_control",
    "admin": "Administrative operations",
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", scopes=SCOPES)
oauth2_scheme_optional = OAuth2PasswordBearer(
    tokenUrl="token", scopes=SCOPES, auto_error=False
)

KNOWN_SCOPES = set(SCOPES.keys())
DEFAULT_USER_SCOPES = os.getenv(
    "DEFAULT_USER_SCOPES",
    "items:read extras:read cars:read"
).split()

OPEN_USER_REGISTRATION = os.getenv("OPEN_USER_REGISTRATION", "true").lower() == "true"

# ------------------------------------------------------------------------------------
# Helpers: scopes & strings
# ------------------------------------------------------------------------------------
def normalize_scopes(scopes: Optional[List[str]]) -> List[str]:
    if not scopes:
        return []
    return sorted(set(s for s in scopes if s in KNOWN_SCOPES))

def parse_scopes_str(s: Optional[str]) -> List[str]:
    return [x for x in (s or "").split() if x]

def join_scopes(scopes: List[str]) -> str:
    return " ".join(sorted(set(scopes)))

def parse_scopes_from_form(s: Optional[str]) -> Optional[List[str]]:
    if not s:
        return None
    parts = re.split(r"[ ,]+", s.strip())
    return [p for p in parts if p]

def _strip_str_values(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str):
            v = v.strip()
        out[k] = v
    return out

# ------------------------------------------------------------------------------------
# Helpers: parsing textboxes (all inputs are strings in Swagger)
# ------------------------------------------------------------------------------------
def _is_blank(x: Optional[str]) -> bool:
    return x is None or (isinstance(x, str) and x.strip() == "")

def as_int(name: str, value: Optional[str], *, required: bool = False) -> Optional[int]:
    if _is_blank(value):
        if required:
            raise HTTPException(status_code=422, detail=f"{name} is required")
        return None
    try:
        return int(value)
    except Exception:
        raise HTTPException(status_code=422, detail=f"{name} must be an integer")

def as_float(name: str, value: Optional[str], *, required: bool = False) -> Optional[float]:
    if _is_blank(value):
        if required:
            raise HTTPException(status_code=422, detail=f"{name} is required")
        return None
    try:
        return float(value)
    except Exception:
        raise HTTPException(status_code=422, detail=f"{name} must be a number")

def as_bool(name: str, value: Optional[str], default: Optional[bool] = None) -> Optional[bool]:
    if _is_blank(value):
        return default
    v = value.strip().lower()
    if v in ("1", "true", "t", "yes", "y", "on"):
        return True
    if v in ("0", "false", "f", "no", "n", "off"):
        return False
    raise HTTPException(status_code=422, detail=f"{name} must be a boolean (true/false)")

def as_str_or_none(value: Optional[str]) -> Optional[str]:
    return None if _is_blank(value) else value

# ------------------------------------------------------------------------------------
# Pydantic Response Schemas
# ------------------------------------------------------------------------------------
class Item(BaseModel):
    id: int
    name: str
    description: str
    price: float

class Extra(BaseModel):
    extras_code: Optional[str] = None
    name: Optional[str] = None
    english_name: Optional[str] = None
    extra_unit: Optional[int] = None
    extra_group: Optional[int] = None
    vat: Optional[float] = None
    vat_code: Optional[str] = None
    inventory: Optional[str] = None
    gl_code: Optional[str] = None
    gl_code_sl: Optional[str] = None
    international_code: Optional[str] = None
    allow_in_cs: Optional[int] = None
    allow_in_web: Optional[int] = None
    allow_in_client: Optional[int] = None
    allow_in_portal: Optional[int] = None
    ext_extra_for: Optional[str] = None
    calculate_vat: Optional[str] = None
    inventory_by_subextra: Optional[int] = None
    sub_extra_lastno: Optional[int] = None
    flat_amount_yn: Optional[str] = None

class CarControl(BaseModel):
    unit_no: Optional[str] = None
    license_no: Optional[str] = None
    company_code: Optional[int] = None
    fleet_assignment: Optional[str] = None
    f_group: Optional[str] = None
    car_make: Optional[int] = None
    model: Optional[int] = None
    color: Optional[str] = None
    car_status: Optional[int] = None
    owner_country: Optional[str] = None
    check_out_date: Optional[str] = None
    check_out_time: Optional[int] = None
    check_out_branach: Optional[int] = None
    check_in_date: Optional[str] = None
    check_in_time: Optional[int] = None
    check_in_branach: Optional[int] = None
    branach: Optional[int] = None
    country: Optional[str] = None
    current_odometer: Optional[int] = None
    out_of_service_reas: Optional[int] = None
    vehicle_type: Optional[str] = None
    parking_lot_code: Optional[int] = None
    parking_space: Optional[int] = None
    sale_cycle: Optional[int] = None
    last_document_type: Optional[str] = None
    last_document_no: Optional[float] = None
    last_suv_agreement: Optional[int] = None
    odometer_after_min: Optional[int] = None
    reserved_to: Optional[str] = None
    garage: Optional[int] = None
    smoke: Optional[str] = None
    telephone: Optional[str] = None
    taxilimo_chauffeur: Optional[str] = None
    prechecked_in_place: Optional[str] = None
    fleet_sub_assignment: Optional[int] = None
    deposit_note: Optional[float] = None
    europcar_company: Optional[str] = None
    petrol_level: Optional[int] = None
    transaction_user: Optional[str] = None
    transaction_date: Optional[str] = None
    transaction_time: Optional[int] = None
    mortgaged_to: Optional[int] = None
    crc_inter_agr: Optional[int] = None
    lease_document: Optional[int] = None
    lease_srno: Optional[int] = None
    lease_document_type: Optional[str] = None
    lease_last_agreement: Optional[int] = None
    lease_last_sub_agrno: Optional[int] = None
    lease_veh_type: Optional[str] = None
    crc_chauffeur: Optional[str] = None
    location: Optional[int] = None
    sub_status: Optional[int] = None
    promotional_veh: Optional[str] = None
    mark_preready_stat: Optional[str] = None
    yard_no: Optional[int] = None
    awxx_last_update_date: Optional[str] = None
    class Config:
        schema_extra = {"example": {
        "unit_no": "100100000",
        "license_no": "6929HJD",
        "company_code": 1,
        "fleet_assignment": "B",
        "f_group": "FFAR",
        "car_make": 10,
        "model": 7,
        "color": "RED",
        "car_status": 7,
        "owner_country": "KSA",
        "check_out_date": "20251001",
        "check_out_time": 48480,
        "check_out_branach": 1,
        "check_in_date": "20251001",
        "check_in_time": 48540,
        "check_in_branach": 1,
        "branach": 1,
        "country": "KSA",
        "current_odometer": 100,
        "out_of_service_reas": 0,
        "vehicle_type": "VT",
        "parking_lot_code": 1,
        "parking_space": 1,
        "sale_cycle": 0,
        "last_document_type": "Y",
        "last_document_no": 1,
        "last_suv_agreement": 1,
        "odometer_after_min": 0,
        "reserved_to": "RSV000000012",
        "garage": 0,
        "smoke": "N",
        "telephone": "0555555555",
        "taxilimo_chauffeur": "NA",
        "prechecked_in_place": "Yard A",
        "fleet_sub_assignment": 0,
        "deposit_note": 0,
        "europcar_company": "N",
        "petrol_level": 0,
        "transaction_user": "BUGZY",
        "transaction_date": "20251001",
        "transaction_time": 0,
        "mortgaged_to": 0,
        "crc_inter_agr": 0,
        "lease_document": 0,
        "lease_srno": 0,
        "lease_document_type": "L",
        "lease_last_agreement": 0,
        "lease_last_sub_agrno": 0,
        "lease_veh_type": "SEDAN",
        "crc_chauffeur": "NA",
        "location": 0,
        "sub_status": 0,
        "promotional_veh": "N",
        "mark_preready_stat": "N",
        "yard_no": 0,
        "awxx_last_update_date": "2025-10-02T07:00:00Z"
} }


def to_item(row: Dict[str, Any]) -> Item:
    price = row["price"]
    if isinstance(price, Decimal):
        price = float(price)
    return Item(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        price=price,
    )

def to_extra(row: Dict[str, Any]) -> Extra:
    r = {k: (v.strip() if isinstance(v, str) else v) for k, v in dict(row).items()}
    if "vat" in r and isinstance(r["vat"], Decimal):
        r["vat"] = float(r["vat"])
    return Extra(**r)

def to_car_control(row: Dict[str, Any]) -> CarControl:
    # Trim trailing spaces from all string fields before returning
    r = {k: (v.rstrip() if isinstance(v, str) else v) for k, v in dict(row).items()}
    return CarControl(**r)
# ------------------------------------------------------------------------------------
# SQLAlchemy Core Table Definitions
# ------------------------------------------------------------------------------------
items_table = Table(
    "items",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(200), nullable=False),
    Column("description", String, nullable=False),
    Column("price", Numeric(18, 2), nullable=False),
)

extras_table = Table(
    "extras",
    metadata,
    Column("extras_code", String(3), primary_key=True),
    Column("name", String(30)),
    Column("english_name", String(15)),
    Column("extra_unit", Integer),
    Column("extra_group", Integer),
    Column("vat", Numeric(18, 6)),
    Column("vat_code", String(14)),
    Column("inventory", String(1)),
    Column("gl_code", String(20)),
    Column("gl_code_sl", String(20)),
    Column("international_code", String(8)),
    Column("allow_in_cs", Integer),
    Column("allow_in_web", Integer),
    Column("allow_in_client", Integer),
    Column("allow_in_portal", Integer),
    Column("ext_extra_for", String(1)),
    Column("calculate_vat", String(1)),
    Column("inventory_by_subextra", Integer),
    Column("sub_extra_lastno", Integer),
    Column("flat_amount_yn", String(1)),
)

car_control_table = Table(
    "car_control",
    metadata,
    Column("unit_no", String(10), primary_key=True, nullable=True),
    Column("license_no", String(10), nullable=True),
    Column("company_code", SmallInteger, nullable=True),
    Column("fleet_assignment", String(1), nullable=True),
    Column("f_group", String(5), nullable=True),
    Column("car_make", SmallInteger, nullable=True),
    Column("model", Integer, nullable=True),
    Column("color", String(10), nullable=True),
    Column("car_status", SmallInteger, nullable=True),
    Column("owner_country", String(3), nullable=True),
    Column("check_out_date", String(8), nullable=True),
    Column("check_out_time", Integer, nullable=True),
    Column("check_out_branach", Integer, nullable=True),
    Column("check_in_date", String(8), nullable=True),
    Column("check_in_time", Integer, nullable=True),
    Column("check_in_branach", Integer, nullable=True),
    Column("branach", Integer, nullable=True),
    Column("country", String(3), nullable=True),
    Column("current_odometer", Integer, nullable=True),
    Column("out_of_service_reas", SmallInteger, nullable=True),
    Column("vehicle_type", String(2), nullable=True),
    Column("parking_lot_code", SmallInteger, nullable=True),
    Column("parking_space", SmallInteger, nullable=True),
    Column("sale_cycle", SmallInteger, nullable=True),
    Column("last_document_type", String(1), nullable=True),
    Column("last_document_no", Float, nullable=True),
    Column("last_suv_agreement", SmallInteger, nullable=True),
    Column("odometer_after_min", Integer, nullable=True),
    Column("reserved_to", String(12), nullable=True),
    Column("garage", Integer, nullable=True),
    Column("smoke", String(1), nullable=True),
    Column("telephone", String(20), nullable=True),
    Column("taxilimo_chauffeur", String(10), nullable=True),
    Column("prechecked_in_place", String(40), nullable=True),
    Column("fleet_sub_assignment", SmallInteger, nullable=True),
    Column("deposit_note", Float, nullable=True),
    Column("europcar_company", String(1), nullable=True),
    Column("petrol_level", SmallInteger, nullable=True),
    Column("transaction_user", String(15), nullable=True),
    Column("transaction_date", String(8), nullable=True),
    Column("transaction_time", Integer, nullable=True),
    Column("mortgaged_to", Integer, nullable=True),
    Column("crc_inter_agr", Integer, nullable=True),
    Column("lease_document", Integer, nullable=True),
    Column("lease_srno", SmallInteger, nullable=True),
    Column("lease_document_type", String(1), nullable=True),
    Column("lease_last_agreement", Integer, nullable=True),
    Column("lease_last_sub_agrno", SmallInteger, nullable=True),
    Column("lease_veh_type", Text, nullable=True),
    Column("crc_chauffeur", String(10), nullable=True),
    Column("location", SmallInteger, nullable=True),
    Column("sub_status", Integer, nullable=True),
    Column("promotional_veh", String(1), nullable=True),
    Column("mark_preready_stat", String(1), nullable=True),
    Column("yard_no", Integer, nullable=True),
    Column("awxx_last_update_date", String(20), nullable=True),
)

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(50), unique=True, nullable=False),
    Column("hashed_password", String, nullable=False),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("scopes", String, nullable=True),
    Column("token_version", Integer, nullable=False, server_default=text("1")),
)

# ------------------------------------------------------------------------------------
# DB Session Dependency
# ------------------------------------------------------------------------------------
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------------------------------------------------------------------
# Auth Helpers
# ------------------------------------------------------------------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def get_user_by_username(db: Session, username: str) -> Optional[Dict[str, Any]]:
    row = db.execute(
        select(users_table).where(users_table.c.username == username)
    ).mappings().first()
    return dict(row) if row else None

def authenticate_user(db: Session, username: str, password: str) -> Optional[Dict[str, Any]]:
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    if not user.get("is_active", True):
        return None
    return user

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> "User":
    auth_header = f'Bearer scope="{security_scopes.scope_str}"' if security_scopes.scopes else "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": auth_header},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if is_token_revoked(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": auth_header},
            )
        username: Optional[str] = payload.get("sub")
        token_scopes: List[str] = payload.get("scopes", [])
        token_ver: int = int(payload.get("ver", 1))
        if username is None:
            raise credentials_exception
        for scope in security_scopes.scopes:
            if scope not in token_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": auth_header},
                )
        user_record = get_user_by_username(db, username)
        if not user_record:
            raise credentials_exception
        current_ver = int(user_record.get("token_version", 1))
        if token_ver != current_ver:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": auth_header},
            )
        return User(username=user_record["username"], is_active=user_record.get("is_active", True))
    except JWTError:
        raise credentials_exception

class User(BaseModel):
    username: str
    is_active: bool = True

def get_current_active_user(
    current_user: User = Security(get_current_user, scopes=[])
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def require_admin_if_closed(token: Optional[str], db: Session) -> None:
    if OPEN_USER_REGISTRATION:
        return
    auth_header = 'Bearer scope="admin"'
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": auth_header},
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        token_scopes: List[str] = payload.get("scopes", [])
        if (username is None) or ("admin" not in token_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin scope required",
                headers={"WWW-Authenticate": auth_header},
            )
        user_record = get_user_by_username(db, username)
        if not user_record or not user_record.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or inactive user",
                headers={"WWW-Authenticate": auth_header},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": auth_header},
        )

# ------------------------------------------------------------------------------------
# Helper Functions (ordering & filters)
# ------------------------------------------------------------------------------------
def apply_ordering(query, table, order_by: Optional[str], default_col: str) -> Tuple[Any, Optional[str]]:
    if not order_by:
        col = getattr(table.c, default_col, None)
        if col is not None:
            return query.order_by(col.asc()), f"{default_col}:asc"
        return query, None
    parts = order_by.split(":")
    col_name = parts[0].strip()
    direction = parts[1].strip().lower() if len(parts) > 1 else "asc"
    col = getattr(table.c, col_name, None)
    if col is None:
        return query, None
    if direction not in ("asc", "desc"):
        direction = "asc"
    query = query.order_by(col.asc() if direction == "asc" else col.desc())
    return query, f"{col_name}:{direction}"

def like_or_equals(col, value: Optional[str], partial: bool):
    if value is None:
        return None
    return col.ilike(f"%{value}%") if partial else (col == value)

# ------------------------------------------------------------------------------------
# Auth: Token endpoint (manual Form fields, blank textboxes)
# ------------------------------------------------------------------------------------
@app.post("/token", tags=["Auth"])
def login_for_access_token(
    username: str = Form(..., example=""),
    password: str = Form(..., example=""),
    scope: Optional[str] = Form("", description="Optional scopes (space separated)", example=""),
    grant_type: Optional[str] = Form("", description="Leave blank (treated as password grant)", example=""),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    requested = normalize_scopes(parse_scopes_from_form(scope) or [])
    allowed = normalize_scopes(parse_scopes_str(user.get("scopes")) or DEFAULT_USER_SCOPES)
    granted = requested if requested else allowed
    granted = [s for s in granted if s in allowed and s in KNOWN_SCOPES]
    ver = int(user.get("token_version", 1))
    access_token = create_access_token(
        data={"sub": user["username"], "scopes": granted, "ver": ver}
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ------------------------------------------------------------------------------------
# Users: Register (Form-only), Me, Logout
# ------------------------------------------------------------------------------------
@app.post("/users/register", status_code=201, tags=["Users"])
def register_user(
    username: str = Form(..., min_length=3, max_length=50, description="Letters, digits, underscore, dot, dash", example=""),
    password: str = Form(..., min_length=8, description="At least 8 characters", example=""),
    scopes_text: Optional[str] = Form("", description="Optional scopes (space/comma separated)", example=""),
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional),
):
    require_admin_if_closed(token, db)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
        raise HTTPException(
            status_code=422,
            detail="Username must be 3–50 chars; allowed: letters, numbers, underscore, dot, dash",
        )
    exists = db.execute(
        select(users_table.c.id).where(users_table.c.username == username)
    ).scalar()
    if exists:
        raise HTTPException(status_code=409, detail="Username already exists")

    scopes_in = parse_scopes_from_form(scopes_text)
    scopes = normalize_scopes(scopes_in) if scopes_in is not None else normalize_scopes(DEFAULT_USER_SCOPES)

    db.execute(
        insert(users_table).values(
            username=username,
            hashed_password=get_password_hash(password),
            is_active=True,
            scopes=join_scopes(scopes),
            token_version=1,
        )
    )
    db.commit()
    return {"username": username, "is_active": True, "scopes": scopes}

@app.get("/users/me", response_model=Dict[str, Any], tags=["Users"])
def read_users_me(
    current_user: User = Security(get_current_user, scopes=[]),
    db: Session = Depends(get_db),
):
    rec = db.execute(
        select(users_table).where(users_table.c.username == current_user.username)
    ).mappings().first()
    if not rec:
        raise HTTPException(status_code=404, detail="User not found")
    allowed_scopes = normalize_scopes(parse_scopes_str(rec.get("scopes")))
    return {"username": current_user.username, "is_active": current_user.is_active, "scopes": allowed_scopes}

@app.post("/logout", tags=["Auth"])
def logout_current(
    current_user: User = Security(get_current_user, scopes=[]),
    db: Session = Depends(get_db),
):
    db.execute(
        update(users_table)
        .where(users_table.c.username == current_user.username)
        .values(token_version=text("COALESCE(token_version,1) + 1"))
    )
    db.commit()
    return {"message": "Logged out (all tokens invalidated)"}

# ------------------------------------------------------------------------------------
# CRUD: Items (Form-only for POST/PUT; all textboxes blank)
# ------------------------------------------------------------------------------------
@app.get("/items", response_model=List[Item])
def get_items(
    current_user: User = Security(get_current_user, scopes=["items:read"]),
    db: Session = Depends(get_db),
):
    rows = db.execute(select(items_table)).mappings().all()
    return [to_item(dict(r)) for r in rows]

@app.get("/items/{item_id}", response_model=Item)
def get_item(
    item_id_str: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["items:read"]),
    db: Session = Depends(get_db),
):
    item_id = as_int("item_id", item_id_str, required=True)
    row = db.execute(
        select(items_table).where(items_table.c.id == item_id)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Item not found")
    return to_item(dict(row))

@app.post("/items", response_model=Item, status_code=201)
def create_item(
    id_str: str = Form(..., example=""),
    name: str = Form(..., example="GPS"),
    description: str = Form(..., example=""),
    price_str: str = Form(..., example=""),
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    id_ = as_int("id", id_str, required=True)
    price = as_float("price", price_str, required=True)

    exists = db.execute(
        select(items_table.c.id).where(items_table.c.id == id_)
    ).scalar()
    if exists is not None:
        raise HTTPException(status_code=409, detail=f"Item with id {id_} already exists")

    db.execute(insert(items_table).values(id=id_, name=name.strip(), description=description.strip(), price=price))
    db.commit()

    row = db.execute(
        select(items_table).where(items_table.c.id == id_)
    ).mappings().first()
    return to_item(dict(row))

@app.put("/items/{item_id}", response_model=Item)
def update_item(
    item_id_str: str = Path(..., example=""),
    name: str = Form(..., example="GPS"),
    description: str = Form(..., example=""),
    price_str: str = Form(..., example=""),
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    item_id = as_int("item_id", item_id_str, required=True)
    price = as_float("price", price_str, required=True)

    values = {"name": name.strip(), "description": description.strip(), "price": price}
    res = db.execute(
        update(items_table).where(items_table.c.id == item_id).values(**values)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    db.commit()
    row = db.execute(
        select(items_table).where(items_table.c.id == item_id)
    ).mappings().first()
    return to_item(dict(row))

@app.delete("/items/{item_id}")
def delete_item(
    item_id_str: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    item_id = as_int("item_id", item_id_str, required=True)
    res = db.execute(delete(items_table).where(items_table.c.id == item_id))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    db.commit()
    return {"message": "Item deleted"}

# ------------------------------------------------------------------------------------
# Extras — Form-only for POST/PUT; blank query textboxes for GET
# ------------------------------------------------------------------------------------
@app.get("/extras", response_model=List[Extra], tags=["Extras (compat)"])
def get_extras(
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
    extras_code: Optional[str] = Query("", alias="EXTRAS_CODE", example=""),
    name: Optional[str] = Query("", alias="NAME", example=""),
):
    extras_code = as_str_or_none(extras_code)
    name = as_str_or_none(name)
    if not extras_code and not name:
        raise HTTPException(status_code=422, detail="Either extras_code or name must be provided")
    query = select(extras_table)
    if extras_code:
        query = query.where(extras_table.c.extras_code == extras_code)
    if name:
        query = query.where(extras_table.c.name == name)
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]

@app.get("/extras/{code}", response_model=Extra, tags=["Extras"])
def get_extra(
    code: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
):
    code = code.strip()
    row = db.execute(
        select(extras_table).where(extras_table.c.extras_code == code)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Extra not found")
    return to_extra(dict(row))

@app.post("/extras", response_model=Extra, status_code=201, tags=["Extras"])
def create_extra(
    extras_code: Optional[str] = Form("", example="001"),
    name: Optional[str] = Form("", example="GPS"),
    english_name: Optional[str] = Form("", example="GPS UNIT"),
    extra_unit_str: Optional[str] = Form("", example="1"),
    extra_group_str: Optional[str] = Form("", example="10"),
    vat_str: Optional[str] = Form("", example="15"),
    vat_code: Optional[str] = Form("", example="VAT15"),
    inventory: Optional[str] = Form("", example="Y"),
    gl_code: Optional[str] = Form("", example="5000-000"),
    gl_code_sl: Optional[str] = Form("", example="5000-001"),
    international_code: Optional[str] = Form("", example="INT12345"),
    allow_in_cs_str: Optional[str] = Form("", example="1"),
    allow_in_web_str: Optional[str] = Form("", example="1"),
    allow_in_client_str: Optional[str] = Form("", example="1"),
    allow_in_portal_str: Optional[str] = Form("", example="1"),
    ext_extra_for: Optional[str] = Form("", example="E"),
    calculate_vat: Optional[str] = Form("", example="Y"),
    inventory_by_subextra_str: Optional[str] = Form("", example="0"),
    sub_extra_lastno_str: Optional[str] = Form("", example="0"),
    flat_amount_yn: Optional[str] = Form("", example="N"),
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    extras_code = as_str_or_none(extras_code)
    name = as_str_or_none(name)
    if not extras_code and not name:
        raise HTTPException(status_code=422, detail="Either extras_code or name must be provided")

    if extras_code:
        exists = db.execute(
            select(extras_table.c.extras_code).where(extras_table.c.extras_code == extras_code)
        ).scalar()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"Extra with code {extras_code} already exists")

    payload = {
        "extras_code": extras_code,
        "name": name,
        "english_name": as_str_or_none(english_name),
        "extra_unit": as_int("extra_unit", extra_unit_str) ,
        "extra_group": as_int("extra_group", extra_group_str),
        "vat": as_float("vat", vat_str),
        "vat_code": as_str_or_none(vat_code),
        "inventory": as_str_or_none(inventory),
        "gl_code": as_str_or_none(gl_code),
        "gl_code_sl": as_str_or_none(gl_code_sl),
        "international_code": as_str_or_none(international_code),
        "allow_in_cs": as_int("allow_in_cs", allow_in_cs_str),
        "allow_in_web": as_int("allow_in_web", allow_in_web_str),
        "allow_in_client": as_int("allow_in_client", allow_in_client_str),
        "allow_in_portal": as_int("allow_in_portal", allow_in_portal_str),
        "ext_extra_for": as_str_or_none(ext_extra_for),
        "calculate_vat": as_str_or_none(calculate_vat),
        "inventory_by_subextra": as_int("inventory_by_subextra", inventory_by_subextra_str),
        "sub_extra_lastno": as_int("sub_extra_lastno", sub_extra_lastno_str),
        "flat_amount_yn": as_str_or_none(flat_amount_yn),
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    payload = _strip_str_values(payload)

    db.execute(insert(extras_table).values(**payload))
    db.commit()

    row = None
    if extras_code:
        row = db.execute(
            select(extras_table).where(extras_table.c.extras_code == extras_code)
        ).mappings().first()
    return to_extra(dict(row)) if row else Extra(**payload)

@app.put("/extras/{code}", response_model=Extra, tags=["Extras"])
def update_extra(
    code: str = Path(..., example=""),
    name: Optional[str] = Form("", example="GPS"),
    english_name: Optional[str] = Form("", example="GPS UNIT"),
    extra_unit_str: Optional[str] = Form("", example="1"),
    extra_group_str: Optional[str] = Form("", example="10"),
    vat_str: Optional[str] = Form("", example="15"),
    vat_code: Optional[str] = Form("", example="VAT15"),
    inventory: Optional[str] = Form("", example="Y"),
    gl_code: Optional[str] = Form("", example="5000-000"),
    gl_code_sl: Optional[str] = Form("", example="5000-001"),
    international_code: Optional[str] = Form("", example="INT12345"),
    allow_in_cs_str: Optional[str] = Form("", example="1"),
    allow_in_web_str: Optional[str] = Form("", example="1"),
    allow_in_client_str: Optional[str] = Form("", example="1"),
    allow_in_portal_str: Optional[str] = Form("", example="1"),
    ext_extra_for: Optional[str] = Form("", example="E"),
    calculate_vat: Optional[str] = Form("", example="Y"),
    inventory_by_subextra_str: Optional[str] = Form("", example="0"),
    sub_extra_lastno_str: Optional[str] = Form("", example="0"),
    flat_amount_yn: Optional[str] = Form("", example="N"),
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    code = code.strip()
    vals = {
        "name": as_str_or_none(name),
        "english_name": as_str_or_none(english_name),
        "extra_unit": as_int("extra_unit", extra_unit_str),
        "extra_group": as_int("extra_group", extra_group_str),
        "vat": as_float("vat", vat_str),
        "vat_code": as_str_or_none(vat_code),
        "inventory": as_str_or_none(inventory),
        "gl_code": as_str_or_none(gl_code),
        "gl_code_sl": as_str_or_none(gl_code_sl),
        "international_code": as_str_or_none(international_code),
        "allow_in_cs": as_int("allow_in_cs", allow_in_cs_str),
        "allow_in_web": as_int("allow_in_web", allow_in_web_str),
        "allow_in_client": as_int("allow_in_client", allow_in_client_str),
        "allow_in_portal": as_int("allow_in_portal", allow_in_portal_str),
        "ext_extra_for": as_str_or_none(ext_extra_for),
        "calculate_vat": as_str_or_none(calculate_vat),
        "inventory_by_subextra": as_int("inventory_by_subextra", inventory_by_subextra_str),
        "sub_extra_lastno": as_int("sub_extra_lastno", sub_extra_lastno_str),
        "flat_amount_yn": as_str_or_none(flat_amount_yn),
    }
    vals = {k: v for k, v in vals.items() if v is not None}
    vals = _strip_str_values(vals)
    if not vals:
        raise HTTPException(status_code=422, detail="No fields to update")

    res = db.execute(
        update(extras_table)
        .where(extras_table.c.extras_code == code)
        .values(**vals)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Extra not found")

    db.commit()
    row = db.execute(
        select(extras_table).where(extras_table.c.extras_code == code)
    ).mappings().first()
    return to_extra(dict(row))

@app.delete("/extras/{code}", tags=["Extras"])
def delete_extra(
    code: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    code = code.strip()
    res = db.execute(delete(extras_table).where(extras_table.c.extras_code == code))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Extra not found")
    db.commit()
    return {"message": "Extra deleted"}

@app.get("/extras/list", response_model=List[Extra], tags=["Extras"])
def list_extras(
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
    limit_str: Optional[str] = Query("", example=""),
    offset_str: Optional[str] = Query("", example=""),
    order_by: Optional[str] = Query("", description='e.g. "extras_code:asc"', example=""),
):
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    query = select(extras_table)
    query, _ = apply_ordering(query, extras_table, order_by, default_col="extras_code")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]

@app.get("/extras/search", response_model=List[Extra], tags=["Extras"])
def search_extras(
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
    code: Optional[str] = Query("", alias="EXTRAS_CODE", example=""),
    name: Optional[str] = Query("", alias="NAME", example=""),
    group_str: Optional[str] = Query("", alias="EXTRA_GROUP", example=""),
    inventory: Optional[str] = Query("", alias="INVENTORY", example=""),
    partial_str: Optional[str] = Query("", description="Use partial matches (ILIKE)", example=""),
    limit_str: Optional[str] = Query("", example=""),
    offset_str: Optional[str] = Query("", example=""),
    order_by: Optional[str] = Query("", description='e.g. "name:asc"', example=""),
):
    partial = as_bool("partial", partial_str, default=True)
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    group_val = as_int("EXTRA_GROUP", group_str)

    query = select(extras_table)
    if not _is_blank(code):
        query = query.where(extras_table.c.extras_code.ilike(f"%{code}%") if partial else (extras_table.c.extras_code == code))
    if not _is_blank(name):
        query = query.where(extras_table.c.name.ilike(f"%{name}%") if partial else (extras_table.c.name == name))
    if group_val is not None:
        query = query.where(extras_table.c.extra_group == group_val)
    if not _is_blank(inventory):
        query = query.where(extras_table.c.inventory == inventory)

    query, _ = apply_ordering(query, extras_table, order_by, default_col="extras_code")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]

# ------------------------------------------------------------------------------------
# CAR_CONTROL — Form-only for POST/PUT; blank query textboxes for GET
# ------------------------------------------------------------------------------------
@app.get("/car_control", response_model=List[CarControl], tags=["Car_Control (compat)"])
def get_car_control(
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
    unit_no: Optional[str] = Query("", alias="UNIT_NO", example=""),
    license_no: Optional[str] = Query("", alias="LICENSE_NO", example=""),
    limit_str: Optional[str] = Query("", example=""),
    offset_str: Optional[str] = Query("", example=""),
):
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    query = select(car_control_table)
    if not _is_blank(unit_no):
        query = query.where(car_control_table.c.unit_no == unit_no)
    if not _is_blank(license_no):
        query = query.where(car_control_table.c.license_no == license_no)
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]

@app.get("/car_control/{unit_no}", response_model=CarControl, tags=["Car_Control"])
def get_car_control_one(
    unit_no: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
):
    unit_no = unit_no.strip()
    row = db.execute(
        select(car_control_table).where(car_control_table.c.unit_no == unit_no)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Car control row not found")
    return to_car_control(dict(row))

@app.post("/car_control", response_model=CarControl, status_code=201, tags=["Car_Control"])
def create_car_control(
    unit_no: Optional[str] = Form("", example="100100000"),
    license_no: Optional[str] = Form("", example="6929HJD"),
    company_code_str: Optional[str] = Form("", example="1"),
    fleet_assignment: Optional[str] = Form("", example="B"),
    f_group: Optional[str] = Form("", example="FFAR"),
    car_make_str: Optional[str] = Form("", example="10"),
    model_str: Optional[str] = Form("", example="7"),
    color: Optional[str] = Form("", example="RED"),
    car_status_str: Optional[str] = Form("", example="7"),
    owner_country: Optional[str] = Form("", example="KSA"),
    check_out_date: Optional[str] = Form("", example="20251001"),
    check_out_time_str: Optional[str] = Form("", example="48480"),
    check_out_branach_str: Optional[str] = Form("", example="1"),
    check_in_date: Optional[str] = Form("", example="20251001"),
    check_in_time_str: Optional[str] = Form("", example="48540"),
    check_in_branach_str: Optional[str] = Form("", example="1"),
    branach_str: Optional[str] = Form("", example="1"),
    country: Optional[str] = Form("", example="KSA"),
    current_odometer_str: Optional[str] = Form("", example="100"),
    out_of_service_reas_str: Optional[str] = Form("", example="0"),
    vehicle_type: Optional[str] = Form("", example="VT"),
    parking_lot_code_str: Optional[str] = Form("", example="1"),
    parking_space_str: Optional[str] = Form("", example="1"),
    sale_cycle_str: Optional[str] = Form("", example="0"),
    last_document_type: Optional[str] = Form("", example="Y"),
    last_document_no_str: Optional[str] = Form("", example="1"),
    last_suv_agreement_str: Optional[str] = Form("", example="1"),
    odometer_after_min_str: Optional[str] = Form("", example="0"),
    reserved_to: Optional[str] = Form("", example="RSV000000012"),
    garage_str: Optional[str] = Form("", example="0"),
    smoke: Optional[str] = Form("", example="N"),
    telephone: Optional[str] = Form("", example="0555555555"),
    taxilimo_chauffeur: Optional[str] = Form("", example="NA"),
    prechecked_in_place: Optional[str] = Form("", example="Yard A"),
    fleet_sub_assignment_str: Optional[str] = Form("", example="0"),
    deposit_note_str: Optional[str] = Form("", example="0"),
    europcar_company: Optional[str] = Form("", example="N"),
    petrol_level_str: Optional[str] = Form("", example="0"),
    transaction_user: Optional[str] = Form("", example="BUGZY"),
    transaction_date: Optional[str] = Form("", example="20251001"),
    transaction_time_str: Optional[str] = Form("", example="0"),
    mortgaged_to_str: Optional[str] = Form("", example="0"),
    crc_inter_agr_str: Optional[str] = Form("", example="0"),
    lease_document_str: Optional[str] = Form("", example="0"),
    lease_srno_str: Optional[str] = Form("", example="0"),
    lease_document_type: Optional[str] = Form("", example="L"),
    lease_last_agreement_str: Optional[str] = Form("", example="0"),
    lease_last_sub_agrno_str: Optional[str] = Form("", example="0"),
    lease_veh_type_str: Optional[str] = Form("", example="SEDAN"),
    crc_chauffeur: Optional[str] = Form("", example="NA"),
    location_str: Optional[str] = Form("", example="0"),
    sub_status_str: Optional[str] = Form("", example="0"),
    promotional_veh: Optional[str] = Form("", example="N"),
    mark_preready_stat: Optional[str] = Form("", example="N"),
    yard_no_str: Optional[str] = Form("", example="0"),
    awxx_last_update_date: Optional[str] = Form("", example="2025-10-02T07:00:00Z"),
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    payload = {
        "unit_no": as_str_or_none(unit_no),
        "license_no": as_str_or_none(license_no),
        "company_code": as_int("company_code", company_code_str),
        "fleet_assignment": as_str_or_none(fleet_assignment),
        "f_group": as_str_or_none(f_group),
        "car_make": as_int("car_make", car_make_str),
        "model": as_int("model", model_str),
        "color": as_str_or_none(color),
        "car_status": as_int("car_status", car_status_str),
        "owner_country": as_str_or_none(owner_country),
        "check_out_date": as_str_or_none(check_out_date),
        "check_out_time": as_int("check_out_time", check_out_time_str),
        "check_out_branach": as_int("check_out_branach", check_out_branach_str),
        "check_in_date": as_str_or_none(check_in_date),
        "check_in_time": as_int("check_in_time", check_in_time_str),
        "check_in_branach": as_int("check_in_branach", check_in_branach_str),
        "branach": as_int("branach", branach_str),
        "country": as_str_or_none(country),
        "current_odometer": as_int("current_odometer", current_odometer_str),
        "out_of_service_reas": as_int("out_of_service_reas", out_of_service_reas_str),
        "vehicle_type": as_str_or_none(vehicle_type),
        "parking_lot_code": as_int("parking_lot_code", parking_lot_code_str),
        "parking_space": as_int("parking_space", parking_space_str),
        "sale_cycle": as_int("sale_cycle", sale_cycle_str),
        "last_document_type": as_str_or_none(last_document_type),
        "last_document_no": as_float("last_document_no", last_document_no_str),
        "last_suv_agreement": as_int("last_suv_agreement", last_suv_agreement_str),
        "odometer_after_min": as_int("odometer_after_min", odometer_after_min_str),
        "reserved_to": as_str_or_none(reserved_to),
        "garage": as_int("garage", garage_str),
        "smoke": as_str_or_none(smoke),
        "telephone": as_str_or_none(telephone),
        "taxilimo_chauffeur": as_str_or_none(taxilimo_chauffeur),
        "prechecked_in_place": as_str_or_none(prechecked_in_place),
        "fleet_sub_assignment": as_int("fleet_sub_assignment", fleet_sub_assignment_str),
        "deposit_note": as_float("deposit_note", deposit_note_str),
        "europcar_company": as_str_or_none(europcar_company),
        "petrol_level": as_int("petrol_level", petrol_level_str),
        "transaction_user": as_str_or_none(transaction_user),
        "transaction_date": as_str_or_none(transaction_date),
        "transaction_time": as_int("transaction_time", transaction_time_str),
        "mortgaged_to": as_int("mortgaged_to", mortgaged_to_str),
        "crc_inter_agr": as_int("crc_inter_agr", crc_inter_agr_str),
        "lease_document": as_int("lease_document", lease_document_str),
        "lease_srno": as_int("lease_srno", lease_srno_str),
        "lease_document_type": as_str_or_none(lease_document_type),
        "lease_last_agreement": as_int("lease_last_agreement", lease_last_agreement_str),
        "lease_last_sub_agrno": as_int("lease_last_sub_agrno", lease_last_sub_agrno_str),
        "lease_veh_type": as_str_or_none(lease_veh_type_str),
        "crc_chauffeur": as_str_or_none(crc_chauffeur),
        "location": as_int("location", location_str),
        "sub_status": as_int("sub_status", sub_status_str),
        "promotional_veh": as_str_or_none(promotional_veh),
        "mark_preready_stat": as_str_or_none(mark_preready_stat),
        "yard_no": as_int("yard_no", yard_no_str),
        "awxx_last_update_date": awxx_last_update_date,  # pass-through if provided
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    if not payload:
        raise HTTPException(status_code=422, detail="Request body is empty")

    if "unit_no" in payload and payload["unit_no"]:
        exists = db.execute(
            select(car_control_table.c.unit_no).where(car_control_table.c.unit_no == payload["unit_no"])
        ).scalar()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"unit_no {payload['unit_no']} already exists")

    db.execute(insert(car_control_table).values(**payload))
    db.commit()

    if "unit_no" in payload:
        row = db.execute(
            select(car_control_table).where(car_control_table.c.unit_no == payload["unit_no"])
        ).mappings().first()
        if row:
            return to_car_control(dict(row))
    return to_car_control(payload)
@app.put("/car_control/{unit_no}", response_model=CarControl, tags=["Car_Control"])
def update_car_control(
    unit_no: str = Path(..., example=""),
    license_no: Optional[str] = Form("", example="6929HJD"),
    company_code_str: Optional[str] = Form("", example="1"),
    fleet_assignment: Optional[str] = Form("", example="B"),
    f_group: Optional[str] = Form("", example="FFAR"),
    car_make_str: Optional[str] = Form("", example="10"),
    model_str: Optional[str] = Form("", example="7"),
    color: Optional[str] = Form("", example="RED"),
    car_status_str: Optional[str] = Form("", example="7"),
    owner_country: Optional[str] = Form("", example="KSA"),
    check_out_date: Optional[str] = Form("", example="20251001"),
    check_out_time_str: Optional[str] = Form("", example="48480"),
    check_out_branach_str: Optional[str] = Form("", example="1"),
    check_in_date: Optional[str] = Form("", example="20251001"),
    check_in_time_str: Optional[str] = Form("", example="48540"),
    check_in_branach_str: Optional[str] = Form("", example="1"),
    branach_str: Optional[str] = Form("", example="1"),
    country: Optional[str] = Form("", example="KSA"),
    current_odometer_str: Optional[str] = Form("", example="100"),
    out_of_service_reas_str: Optional[str] = Form("", example="0"),
    vehicle_type: Optional[str] = Form("", example="VT"),
    parking_lot_code_str: Optional[str] = Form("", example="1"),
    parking_space_str: Optional[str] = Form("", example="1"),
    sale_cycle_str: Optional[str] = Form("", example="0"),
    last_document_type: Optional[str] = Form("", example="Y"),
    last_document_no_str: Optional[str] = Form("", example="1"),
    last_suv_agreement_str: Optional[str] = Form("", example="1"),
    odometer_after_min_str: Optional[str] = Form("", example="0"),
    reserved_to: Optional[str] = Form("", example="RSV000000012"),
    garage_str: Optional[str] = Form("", example="0"),
    smoke: Optional[str] = Form("", example="N"),
    telephone: Optional[str] = Form("", example="0555555555"),
    taxilimo_chauffeur: Optional[str] = Form("", example="NA"),
    prechecked_in_place: Optional[str] = Form("", example="Yard A"),
    fleet_sub_assignment_str: Optional[str] = Form("", example="0"),
    deposit_note_str: Optional[str] = Form("", example="0"),
    europcar_company: Optional[str] = Form("", example="N"),
    petrol_level_str: Optional[str] = Form("", example="0"),
    transaction_user: Optional[str] = Form("", example="BUGZY"),
    transaction_date: Optional[str] = Form("", example="20251001"),
    transaction_time_str: Optional[str] = Form("", example="0"),
    mortgaged_to_str: Optional[str] = Form("", example="0"),
    crc_inter_agr_str: Optional[str] = Form("", example="0"),
    lease_document_str: Optional[str] = Form("", example="0"),
    lease_srno_str: Optional[str] = Form("", example="0"),
    lease_document_type: Optional[str] = Form("", example="L"),
    lease_last_agreement_str: Optional[str] = Form("", example="0"),
    lease_last_sub_agrno_str: Optional[str] = Form("", example="0"),
    lease_veh_type_str: Optional[str] = Form("", example="SEDAN"),
    crc_chauffeur: Optional[str] = Form("", example="NA"),
    location_str: Optional[str] = Form("", example="0"),
    sub_status_str: Optional[str] = Form("", example="0"),
    promotional_veh: Optional[str] = Form("", example="N"),
    mark_preready_stat: Optional[str] = Form("", example="N"),
    yard_no_str: Optional[str] = Form("", example="0"),
    awxx_last_update_date: Optional[str] = Form("", example="2025-10-02T07:00:00Z"),
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    unit_no = unit_no.strip()
    payload = {
        "license_no": as_str_or_none(license_no),
        "company_code": as_int("company_code", company_code_str),
        "fleet_assignment": as_str_or_none(fleet_assignment),
        "f_group": as_str_or_none(f_group),
        "car_make": as_int("car_make", car_make_str),
        "model": as_int("model", model_str),
        "color": as_str_or_none(color),
        "car_status": as_int("car_status", car_status_str),
        "owner_country": as_str_or_none(owner_country),
        "check_out_date": as_str_or_none(check_out_date),
        "check_out_time": as_int("check_out_time", check_out_time_str),
        "check_out_branach": as_int("check_out_branach", check_out_branach_str),
        "check_in_date": as_str_or_none(check_in_date),
        "check_in_time": as_int("check_in_time", check_in_time_str),
        "check_in_branach": as_int("check_in_branach", check_in_branach_str),
        "branach": as_int("branach", branach_str),
        "country": as_str_or_none(country),
        "current_odometer": as_int("current_odometer", current_odometer_str),
        "out_of_service_reas": as_int("out_of_service_reas", out_of_service_reas_str),
        "vehicle_type": as_str_or_none(vehicle_type),
        "parking_lot_code": as_int("parking_lot_code", parking_lot_code_str),
        "parking_space": as_int("parking_space", parking_space_str),
        "sale_cycle": as_int("sale_cycle", sale_cycle_str),
        "last_document_type": as_str_or_none(last_document_type),
        "last_document_no": as_float("last_document_no", last_document_no_str),
        "last_suv_agreement": as_int("last_suv_agreement", last_suv_agreement_str),
        "odometer_after_min": as_int("odometer_after_min", odometer_after_min_str),
        "reserved_to": as_str_or_none(reserved_to),
        "garage": as_int("garage", garage_str),
        "smoke": as_str_or_none(smoke),
        "telephone": as_str_or_none(telephone),
        "taxilimo_chauffeur": as_str_or_none(taxilimo_chauffeur),
        "prechecked_in_place": as_str_or_none(prechecked_in_place),
        "fleet_sub_assignment": as_int("fleet_sub_assignment", fleet_sub_assignment_str),
        "deposit_note": as_float("deposit_note", deposit_note_str),
        "europcar_company": as_str_or_none(europcar_company),
        "petrol_level": as_int("petrol_level", petrol_level_str),
        "transaction_user": as_str_or_none(transaction_user),
        "transaction_date": as_str_or_none(transaction_date),
        "transaction_time": as_int("transaction_time", transaction_time_str),
        "mortgaged_to": as_int("mortgaged_to", mortgaged_to_str),
        "crc_inter_agr": as_int("crc_inter_agr", crc_inter_agr_str),
        "lease_document": as_int("lease_document", lease_document_str),
        "lease_srno": as_int("lease_srno", lease_srno_str),
        "lease_document_type": as_str_or_none(lease_document_type),
        "lease_last_agreement": as_int("lease_last_agreement", lease_last_agreement_str),
        "lease_last_sub_agrno": as_int("lease_last_sub_agrno", lease_last_sub_agrno_str),
        "lease_veh_type": as_str_or_none(lease_veh_type_str),
        "crc_chauffeur": as_str_or_none(crc_chauffeur),
        "location": as_int("location", location_str),
        "sub_status": as_int("sub_status", sub_status_str),
        "promotional_veh": as_str_or_none(promotional_veh),
        "mark_preready_stat": as_str_or_none(mark_preready_stat),
        "yard_no": as_int("yard_no", yard_no_str),
        "awxx_last_update_date": awxx_last_update_date,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    if not payload:
        raise HTTPException(status_code=422, detail="No fields to update")

    res = db.execute(
        update(car_control_table)
        .where(car_control_table.c.unit_no == unit_no)
        .values(**payload)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Car control row not found")

    db.commit()
    row = db.execute(
        select(car_control_table).where(car_control_table.c.unit_no == unit_no)
    ).mappings().first()
    return to_car_control(dict(row))

@app.delete("/car_control/{unit_no}", tags=["Car_Control"])
def delete_car_control(
    unit_no: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    unit_no = unit_no.strip()
    res = db.execute(delete(car_control_table).where(car_control_table.c.unit_no == unit_no))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Car control row not found")
    db.commit()
    return {"message": "Car control row deleted"}

@app.get("/car_control/list", response_model=List[CarControl], tags=["Car_Control"])
def list_car_control(
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
    limit_str: Optional[str] = Query("", example=""),
    offset_str: Optional[str] = Query("", example=""),
    order_by: Optional[str] = Query("", description='e.g. "unit_no:asc"', example=""),
):
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    query = select(car_control_table)
    query, _ = apply_ordering(query, car_control_table, order_by, default_col="unit_no")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]

@app.get("/car_control/search", response_model=List[CarControl], tags=["Car_Control"])
def search_car_control(
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
    unit_no: Optional[str] = Query("", alias="UNIT_NO", example=""),
    license_no: Optional[str] = Query("", alias="LICENSE_NO", example=""),
    car_status_str: Optional[str] = Query("", alias="CAR_STATUS", example=""),
    vehicle_type: Optional[str] = Query("", alias="VEHICLE_TYPE", example=""),
    color: Optional[str] = Query("", alias="COLOR", example=""),
    country: Optional[str] = Query("", alias="COUNTRY", example=""),
    partial_str: Optional[str] = Query("", description="Use partial matches (ILIKE) for text fields", example=""),
    limit_str: Optional[str] = Query("", example=""),
    offset_str: Optional[str] = Query("", example=""),
    order_by: Optional[str] = Query("", description='e.g. "unit_no:asc"', example=""),
):
    partial = as_bool("partial", partial_str, default=True)
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    car_status = as_int("CAR_STATUS", car_status_str)

    query = select(car_control_table)
    if not _is_blank(unit_no):
        query = query.where(car_control_table.c.unit_no.ilike(f"%{unit_no}%") if partial else (car_control_table.c.unit_no == unit_no))
    if not _is_blank(license_no):
        query = query.where(car_control_table.c.license_no.ilike(f"%{license_no}%") if partial else (car_control_table.c.license_no == license_no))
    if car_status is not None:
        query = query.where(car_control_table.c.car_status == car_status)
    if not _is_blank(vehicle_type):
        query = query.where(car_control_table.c.vehicle_type == vehicle_type)
    if not _is_blank(color):
        query = query.where(car_control_table.c.color.ilike(f"%{color}%") if partial else (car_control_table.c.color == color))
    if not _is_blank(country):
        query = query.where(car_control_table.c.country == country)

    query, _ = apply_ordering(query, car_control_table, order_by, default_col="unit_no")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]

# ------------------------------------------------------------------------------------
# Health Check (open)
# ------------------------------------------------------------------------------------
@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ------------------------------------------------------------------------------------
# Startup
# ------------------------------------------------------------------------------------
@app.on_event("startup")
def ensure_tables_and_seed_user():
    metadata.create_all(engine)
    with engine.connect() as conn:
        has_scopes_col = conn.execute(text("""
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'users' AND column_name = 'scopes'
        """)).first()
        if not has_scopes_col:
            conn.execute(text("ALTER TABLE users ADD COLUMN scopes TEXT"))
            conn.commit()
        has_ver_col = conn.execute(text("""
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'users' AND column_name = 'token_version'
        """)).first()
        if not has_ver_col:
            conn.execute(text("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1"))
            conn.commit()

    seed = os.getenv("SEED_DEFAULT_USER", "true").lower() == "true"
    if not seed:
        return
    with SessionLocal() as db:
        existing = db.execute(
            select(users_table.c.username).where(users_table.c.username == "bugzy")
        ).first()
        if not existing:
            seed_scopes = [
                "items:read", "items:write",
                "extras:read", "extras:write",
                "cars:read", "cars:write",
                "admin",
            ]
            db.execute(
                insert(users_table).values(
                    username="bugzy",
                    hashed_password=get_password_hash("P@ssw0rd!"),
                    is_active=True,
                    scopes=join_scopes(seed_scopes),
                    token_version=1,
                )
            )
            db.commit()