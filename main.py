import os
import re
from datetime import datetime, timedelta
from decimal import Decimal
from typing import List, Optional, Dict, Any, Tuple

from fastapi import FastAPI, HTTPException, Depends, Query, status, Security
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
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
    Float as SAFloat,
    text,
)
from sqlalchemy.orm import sessionmaker, Session

# ------------------------------------------------------------------------------------
# FastAPI App
# ------------------------------------------------------------------------------------
app = FastAPI(title="Bugzy Test API Development")

# ------------------------------------------------------------------------------------
# Database: PostgreSQL (Neon) via psycopg2
# ------------------------------------------------------------------------------------
DEFAULT_DB_URL = (
    "postgresql+psycopg2://"
    "neondb_owner:npg_1bIsEeYG6uTP@"
    "ep-proud-leaf-afdhzdfz-pooler.c-2.us-west-2.aws.neon.tech/"
    "BugzyTestAPIDB?sslmode=require"
)
# Correctly normalize any '&' that may appear when pasting from HTML
CONN_STR = os.getenv("DB_URL", DEFAULT_DB_URL).replace("&", "&")

engine = create_engine(
    CONN_STR,
    future=True,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
metadata = MetaData()

# ------------------------------------------------------------------------------------
# OAuth2 / JWT configuration (patched: use SCOPES constant, don't read oauth2_scheme.scopes)
# ------------------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-please")  # set in env for prod
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# ------------------------------------------------------------------------------------
# Token Revocation Logic
# ------------------------------------------------------------------------------------
revoked_tokens: Dict[str, datetime] = {}

def revoke_token(token: str):
    try:
        from jose import JWTError, jwt
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if exp:
            revoked_tokens[token] = datetime.utcfromtimestamp(exp)
    except Exception:
        pass

def is_token_revoked(token: str) -> bool:
    return token in revoked_tokens

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Define SCOPES once and reuse it
SCOPES: Dict[str, str] = {
    "items:read": "Read items",
    "items:write": "Create/update/delete items",
    "extras:read": "Read extras",
    "extras:write": "Create/update/delete extras",
    "cars:read": "Read car_control",
    "cars:write": "Create/update/delete car_control",
    "admin": "Administrative operations",
}

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes=SCOPES,
)

# Optional scheme for endpoints that may accept missing token (admin-gated registration)
oauth2_scheme_optional = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes=SCOPES,
    auto_error=False,  # don't auto-raise 401 when token missing
)

# Known scopes set (derive from SCOPES constant)
KNOWN_SCOPES = set(SCOPES.keys())

# Default scopes for new users (read-only by default)
DEFAULT_USER_SCOPES = os.getenv(
    "DEFAULT_USER_SCOPES",
    "items:read extras:read cars:read"
).split()

# Toggle: allow public self-registration (True) or admin-only (False)
OPEN_USER_REGISTRATION = os.getenv("OPEN_USER_REGISTRATION", "true").lower() == "true"


def normalize_scopes(scopes: Optional[List[str]]) -> List[str]:
    """Return unique, sorted scopes filtered to KNOWN_SCOPES."""
    if not scopes:
        return []
    return sorted(set(s for s in scopes if s in KNOWN_SCOPES))


def parse_scopes_str(s: Optional[str]) -> List[str]:
    return [x for x in (s or "").split() if x]


def join_scopes(scopes: List[str]) -> str:
    return " ".join(sorted(set(scopes)))


# ------------------------------------------------------------------------------------
# Pydantic Schemas (lowercase)
# ------------------------------------------------------------------------------------
class Item(BaseModel):
    id: int
    name: str
    description: str
    price: float


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


def to_extra(row: Dict[str, Any]) -> Extra:
    r = dict(row)
    if "vat" in r and isinstance(r["vat"], Decimal):
        r["vat"] = float(r["vat"])
    return Extra(**r)


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
    lease_veh_type: Optional[int] = None
    crc_chauffeur: Optional[str] = None
    location: Optional[int] = None
    sub_status: Optional[int] = None
    promotional_veh: Optional[str] = None
    mark_preready_stat: Optional[str] = None
    yard_no: Optional[int] = None
    awxx_last_update_date: Optional[datetime] = None


def to_car_control(row: Dict[str, Any]) -> CarControl:
    return CarControl(**row)


# Auth-related Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: List[str] = []


class User(BaseModel):
    username: str
    is_active: bool = True


class UserCreate(BaseModel):
    username: str
    password: str
    scopes: Optional[List[str]] = None  # optional, defaults to DEFAULT_USER_SCOPES


class UserOut(BaseModel):
    username: str
    is_active: bool = True
    scopes: List[str] = []


# ------------------------------------------------------------------------------------
# SQLAlchemy Core Table Definitions (public schema, lowercase)
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
    Column("extras_code", String(3)),
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
    Column("unit_no", String(10), nullable=True),
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
    Column("parking_space", Integer, nullable=True),
    Column("sale_cycle", SmallInteger, nullable=True),
    Column("last_document_type", String(1), nullable=True),
    Column("last_document_no", SAFloat, nullable=True),
    Column("last_suv_agreement", SmallInteger, nullable=True),
    Column("odometer_after_min", Integer, nullable=True),
    Column("reserved_to", String(12), nullable=True),
    Column("garage", Integer, nullable=True),
    Column("smoke", String(1), nullable=True),
    Column("telephone", String(20), nullable=True),
    Column("taxilimo_chauffeur", String(10), nullable=True),
    Column("prechecked_in_place", String(40), nullable=True),
    Column("fleet_sub_assignment", SmallInteger, nullable=True),
    Column("deposit_note", SAFloat, nullable=True),
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
    Column("lease_veh_type", SmallInteger, nullable=True),
    Column("crc_chauffeur", String(10), nullable=True),
    Column("location", SmallInteger, nullable=True),
    Column("sub_status", SmallInteger, nullable=True),
    Column("promotional_veh", String(1), nullable=True),
    Column("mark_preready_stat", String(1), nullable=True),
    Column("yard_no", Integer, nullable=True),
    Column("awxx_last_update_date", DateTime, nullable=True),
)

# Users table for authentication (with scopes)
users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(50), unique=True, nullable=False),
    Column("hashed_password", String, nullable=False),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("scopes", String, nullable=True),  # space-separated scopes
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
# Auth Helper Functions
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
) -> User:
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
        if username is None:
            raise credentials_exception
        # Ensure required scopes are present
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
        return User(username=user_record["username"], is_active=user_record.get("is_active", True))
    except JWTError:
        raise credentials_exception


def get_current_active_user(
    current_user: User = Security(get_current_user, scopes=[])
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Helper used by /users/register when OPEN_USER_REGISTRATION is False
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
        # ensure user still exists and is active
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
    """
    order_by format: "column" or "column:asc|desc"
    Returns (query, applied_ordering_string)
    """
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
    if partial:
        # For case-insensitive on Postgres, switch to col.ilike(...)
        return col.like(f"%{value}%")
    return col == value

# ------------------------------------------------------------------------------------
# Auth: Token endpoint (password grant; grants only allowed scopes)
# ------------------------------------------------------------------------------------
@app.post("/token", response_model=Token, tags=["Auth"])
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    if form_data.grant_type and form_data.grant_type.lower() != "password":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant_type",
        )

    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        # Do not reveal whether username or password failed
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Requested scopes from client
    requested = normalize_scopes(form_data.scopes or [])

    # Allowed scopes for user (from DB) or default
    allowed = normalize_scopes(parse_scopes_str(user.get("scopes")) or DEFAULT_USER_SCOPES)

    # Grant intersection; if none requested, grant all allowed
    granted = requested if requested else allowed
    granted = [s for s in granted if s in allowed and s in KNOWN_SCOPES]

    access_token = create_access_token(
        data={"sub": user["username"], "scopes": granted}
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ------------------------------------------------------------------------------------
# Users: Register & Me
# ------------------------------------------------------------------------------------
@app.post("/users/register", response_model=UserOut, status_code=201, tags=["Users"])
def register_user(
    user_in: UserCreate,
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional),  # optional unless CLOSED
):
    # If registration is closed, only admin can register users
    require_admin_if_closed(token, db)

    # Basic validations
    if not (3 <= len(user_in.username) <= 50) or not re.match(r"^[A-Za-z0-9_.-]+$", user_in.username):
        raise HTTPException(status_code=422, detail="Username must be 3-50 chars; allowed: letters, numbers, underscore, dot, dash")
    if len(user_in.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")

    # Uniqueness
    exists = db.execute(
        select(users_table.c.id).where(users_table.c.username == user_in.username)
    ).scalar()
    if exists:
        raise HTTPException(status_code=409, detail="Username already exists")

    # Scopes: use provided (filtered) or defaults
    scopes = normalize_scopes(user_in.scopes) if user_in.scopes is not None else normalize_scopes(DEFAULT_USER_SCOPES)

    db.execute(
        insert(users_table).values(
            username=user_in.username,
            hashed_password=get_password_hash(user_in.password),
            is_active=True,
            scopes=join_scopes(scopes),
        )
    )
    db.commit()

    return UserOut(username=user_in.username, is_active=True, scopes=scopes)


@app.get("/users/me", response_model=UserOut, tags=["Users"])
def read_users_me(
    current_user: User = Security(get_current_user, scopes=[]),
    db: Session = Depends(get_db),
):
    # Fetch full record to expose scopes
    rec = db.execute(
        select(users_table).where(users_table.c.username == current_user.username)
    ).mappings().first()
    if not rec:
        # Extremely rare: token user no longer exists
        raise HTTPException(status_code=404, detail="User not found")
    allowed_scopes = normalize_scopes(parse_scopes_str(rec.get("scopes")))
    return UserOut(username=current_user.username, is_active=current_user.is_active, scopes=allowed_scopes)

# ------------------------------------------------------------------------------------
# CRUD: Items
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
    item_id: int,
    current_user: User = Security(get_current_user, scopes=["items:read"]),
    db: Session = Depends(get_db),
):
    row = db.execute(
        select(items_table).where(items_table.c.id == item_id)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Item not found")
    return to_item(dict(row))


@app.post("/items", response_model=Item, status_code=201)
def create_item(
    item: Item,
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    exists = db.execute(
        select(items_table.c.id).where(items_table.c.id == item.id)
    ).scalar()
    if exists is not None:
        raise HTTPException(status_code=409, detail=f"Item with id {item.id} already exists")
    db.execute(insert(items_table).values(**item.dict()))
    db.commit()
    row = db.execute(
        select(items_table).where(items_table.c.id == item.id)
    ).mappings().first()
    return to_item(dict(row))


@app.put("/items/{item_id}", response_model=Item)
def update_item(
    item_id: int,
    updated_item: Item,
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    res = db.execute(
        update(items_table).where(items_table.c.id == item_id).values(**updated_item.dict())
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
    item_id: int,
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    res = db.execute(delete(items_table).where(items_table.c.id == item_id))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    db.commit()
    return {"message": "Item deleted"}

# ------------------------------------------------------------------------------------
# Extras (compat & new list/search)
# ------------------------------------------------------------------------------------
@app.get("/extras", response_model=List[Extra], tags=["Extras (compat)"])
def get_extras(
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
    extras_code: Optional[str] = Query(None, alias="EXTRAS_CODE"),
    name: Optional[str] = Query(None, alias="NAME"),
):
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
    code: str,
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
):
    row = db.execute(
        select(extras_table).where(extras_table.c.extras_code == code)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Extra not found")
    return to_extra(dict(row))


@app.post("/extras", response_model=Extra, status_code=201, tags=["Extras"])
def create_extra(
    extra: Extra,
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    if not extra.extras_code and not extra.name:
        raise HTTPException(status_code=422, detail="Either extras_code or name must be provided")
    if extra.extras_code:
        exists = db.execute(
            select(extras_table.c.extras_code).where(extras_table.c.extras_code == extra.extras_code)
        ).scalar()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"Extra with code {extra.extras_code} already exists")
    db.execute(insert(extras_table).values(**extra.dict(exclude_unset=True)))
    db.commit()
    row = None
    if extra.extras_code:
        row = db.execute(
            select(extras_table).where(extras_table.c.extras_code == extra.extras_code)
        ).mappings().first()
    return to_extra(dict(row)) if row else extra


@app.put("/extras/{code}", response_model=Extra, tags=["Extras"])
def update_extra(
    code: str,
    extra: Extra,
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    if not extra.dict(exclude_unset=True):
        raise HTTPException(status_code=422, detail="No fields to update")
    res = db.execute(
        update(extras_table)
        .where(extras_table.c.extras_code == code)
        .values(**extra.dict(exclude_unset=True))
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
    code: str,
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    res = db.execute(delete(extras_table).where(extras_table.c.extras_code == code))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Extra not found")
    db.commit()
    return {"message": "Extra deleted"}


@app.get("/extras/list", response_model=List[Extra], tags=["Extras"])
def list_extras(
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    order_by: Optional[str] = Query(None, description='e.g. "extras_code:asc" or "name:desc"'),
):
    query = select(extras_table)
    query, _ = apply_ordering(query, extras_table, order_by, default_col="extras_code")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]


@app.get("/extras/search", response_model=List[Extra], tags=["Extras"])
def search_extras(
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
    code: Optional[str] = Query(None, alias="EXTRAS_CODE"),
    name: Optional[str] = Query(None, alias="NAME"),
    group_: Optional[int] = Query(None, alias="EXTRA_GROUP"),
    inventory: Optional[str] = Query(None, alias="INVENTORY"),
    partial: bool = Query(True, description="Use partial matches (LIKE)"),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    order_by: Optional[str] = Query(None, description='e.g. "name:asc"'),
):
    query = select(extras_table)
    filters = []
    f = like_or_equals
    if code is not None:
        filters.append(f(extras_table.c.extras_code, code, partial))
    if name is not None:
        filters.append(f(extras_table.c.name, name, partial))
    if group_ is not None:
        filters.append(extras_table.c.extra_group == group_)
    if inventory is not None:
        filters.append(f(extras_table.c.inventory, inventory, partial=False))
    for cond in filters:
        if cond is not None:
            query = query.where(cond)
    query, _ = apply_ordering(query, extras_table, order_by, default_col="extras_code")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]

# ------------------------------------------------------------------------------------
# CAR_CONTROL (compat & new list/search)
# ------------------------------------------------------------------------------------
@app.get("/car_control", response_model=List[CarControl], tags=["Car_Control (compat)"])
def get_car_control(
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
    unit_no: Optional[str] = Query(None, alias="UNIT_NO"),
    license_no: Optional[str] = Query(None, alias="LICENSE_NO"),
    limit: int = 100,
    offset: int = 0,
):
    query = select(car_control_table)
    if unit_no:
        query = query.where(car_control_table.c.unit_no == unit_no)
    if license_no:
        query = query.where(car_control_table.c.license_no == license_no)
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]


@app.get("/car_control/{unit_no}", response_model=CarControl, tags=["Car_Control"])
def get_car_control_one(
    unit_no: str,
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
):
    row = db.execute(
        select(car_control_table).where(car_control_table.c.unit_no == unit_no)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Car control row not found")
    return to_car_control(dict(row))


@app.post("/car_control", response_model=CarControl, status_code=201, tags=["Car_Control"])
def create_car_control(
    item: CarControl,
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    payload = item.dict(exclude_unset=True)
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
    return item


@app.put("/car_control/{unit_no}", response_model=CarControl, tags=["Car_Control"])
def update_car_control(
    unit_no: str,
    item: CarControl,
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    payload = item.dict(exclude_unset=True)
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
    unit_no: str,
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    res = db.execute(delete(car_control_table).where(car_control_table.c.unit_no == unit_no))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Car control row not found")
    db.commit()
    return {"message": "Car control row deleted"}


@app.get("/car_control/list", response_model=List[CarControl], tags=["Car_Control"])
def list_car_control(
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    order_by: Optional[str] = Query(None, description='e.g. "unit_no:asc", "car_status:desc"'),
):
    query = select(car_control_table)
    query, _ = apply_ordering(query, car_control_table, order_by, default_col="unit_no")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]


@app.get("/car_control/search", response_model=List[CarControl], tags=["Car_Control"])
def search_car_control(
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
    unit_no: Optional[str] = Query(None, alias="UNIT_NO"),
    license_no: Optional[str] = Query(None, alias="LICENSE_NO"),
    car_status: Optional[int] = Query(None, alias="CAR_STATUS"),
    vehicle_type: Optional[str] = Query(None, alias="VEHICLE_TYPE"),
    color: Optional[str] = Query(None, alias="COLOR"),
    country: Optional[str] = Query(None, alias="COUNTRY"),
    partial: bool = Query(True, description="Use partial matches (LIKE) for text fields"),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    order_by: Optional[str] = Query(None, description='e.g. "unit_no:asc"'),
):
    query = select(car_control_table)
    filters = []
    if unit_no is not None:
        filters.append(like_or_equals(car_control_table.c.unit_no, unit_no, partial))
    if license_no is not None:
        filters.append(like_or_equals(car_control_table.c.license_no, license_no, partial))
    if car_status is not None:
        filters.append(car_control_table.c.car_status == car_status)
    if vehicle_type is not None:
        filters.append(like_or_equals(car_control_table.c.vehicle_type, vehicle_type, partial=False))
    if color is not None:
        filters.append(like_or_equals(car_control_table.c.color, color, partial))
    if country is not None:
        filters.append(like_or_equals(car_control_table.c.country, country, partial=False))
    for cond in filters:
        if cond is not None:
            query = query.where(cond)
    query, _ = apply_ordering(query, car_control_table, order_by, default_col="unit_no")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]

# ------------------------------------------------------------------------------------
# Health Check (left open / no auth)
# ------------------------------------------------------------------------------------
@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ------------------------------------------------------------------------------------
# Startup: create tables, add scopes column if missing, seed default user with scopes
# ------------------------------------------------------------------------------------
@app.on_event("startup")
def ensure_tables_and_seed_user():
    # Create all tables if missing
    metadata.create_all(engine)

    # Ensure 'scopes' column exists on 'users' (for existing DBs)
    with engine.connect() as conn:
        has_scopes_col = conn.execute(text("""
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'users' AND column_name = 'scopes'
        """)).first()
        if not has_scopes_col:
            conn.execute(text("ALTER TABLE users ADD COLUMN scopes TEXT"))
            conn.commit()

    # Seed default user (controlled by env)
    seed = os.getenv("SEED_DEFAULT_USER", "true").lower() == "true"
    if not seed:
        return

    with SessionLocal() as db:
        existing = db.execute(
            select(users_table.c.username).where(users_table.c.username == "bugzy")
        ).first()

        if not existing:
            # Full admin + read/write scopes for convenience
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
                )
            )
