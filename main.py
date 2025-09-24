# main.py
from datetime import datetime
from decimal import Decimal
from typing import List, Optional, Dict, Any, Tuple

from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, Numeric, Float as SAFloat,
    SmallInteger, DateTime, select, insert, update, delete, text
)
from sqlalchemy.orm import sessionmaker, Session

app = FastAPI(title="Bugzy's FastAPI -> SQL Server (CARPRO DB-LIVE)")

# -------------------- Pydantic schemas --------------------
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
    EXTRAS_CODE: Optional[str] = None
    NAME: Optional[str] = None
    ENGLISH_NAME: Optional[str] = None
    EXTRA_UNIT: Optional[int] = None
    EXTRA_GROUP: Optional[int] = None
    VAT: Optional[float] = None
    VAT_CODE: Optional[str] = None
    INVENTORY: Optional[str] = None
    GL_CODE: Optional[str] = None
    GL_CODE_SL: Optional[str] = None
    INTERNATIONAL_CODE: Optional[str] = None
    ALLOW_IN_CS: Optional[int] = None
    ALLOW_IN_WEB: Optional[int] = None
    ALLOW_IN_CLIENT: Optional[int] = None
    ALLOW_IN_PORTAL: Optional[int] = None
    EXT_EXTRA_FOR: Optional[str] = None
    CALCULATE_VAT: Optional[str] = None
    INVENTORY_BY_SUBEXTRA: Optional[int] = None
    SUB_EXTRA_LASTNO: Optional[int] = None
    FLAT_AMOUNT_YN: Optional[str] = None

def to_extra(row: Dict[str, Any]) -> Extra:
    # Coerce Decimal->float for VAT if needed
    r = dict(row)
    if "VAT" in r and isinstance(r["VAT"], Decimal):
        r["VAT"] = float(r["VAT"])
    return Extra(**r)

class CarControl(BaseModel):
    UNIT_NO: Optional[str] = None
    LICENSE_NO: Optional[str] = None
    COMPANY_CODE: Optional[int] = None
    FLEET_ASSIGNMENT: Optional[str] = None
    F_GROUP: Optional[str] = None
    CAR_MAKE: Optional[int] = None
    MODEL: Optional[int] = None
    COLOR: Optional[str] = None
    CAR_STATUS: Optional[int] = None
    OWNER_COUNTRY: Optional[str] = None
    CHECK_OUT_DATE: Optional[str] = None
    CHECK_OUT_TIME: Optional[int] = None
    CHECK_OUT_BRANACH: Optional[int] = None
    CHECK_IN_DATE: Optional[str] = None
    CHECK_IN_TIME: Optional[int] = None
    CHECK_IN_BRANACH: Optional[int] = None
    BRANACH: Optional[int] = None
    COUNTRY: Optional[str] = None
    CURRENT_ODOMETER: Optional[int] = None
    OUT_OF_SERVICE_REAS: Optional[int] = None
    VEHICLE_TYPE: Optional[str] = None
    PARKING_LOT_CODE: Optional[int] = None
    PARKING_SPACE: Optional[int] = None
    SALE_CYCLE: Optional[int] = None
    LAST_DOCUMENT_TYPE: Optional[str] = None
    LAST_DOCUMENT_NO: Optional[float] = None
    LAST_SUV_AGREEMENT: Optional[int] = None
    ODOMETER_AFTER_MIN: Optional[int] = None
    RESERVED_TO: Optional[str] = None
    GARAGE: Optional[int] = None
    SMOKE: Optional[str] = None
    TELEPHONE: Optional[str] = None
    TAXILIMO_CHAUFFEUR: Optional[str] = None
    PRECHECKED_IN_PLACE: Optional[str] = None
    FLEET_SUB_ASSIGNMENT: Optional[int] = None
    DEPOSIT_NOTE: Optional[float] = None
    EUROPCAR_COMPANY: Optional[str] = None
    PETROL_LEVEL: Optional[int] = None
    TRANSACTION_USER: Optional[str] = None
    TRANSACTION_DATE: Optional[str] = None
    TRANSACTION_TIME: Optional[int] = None
    MORTGAGED_TO: Optional[int] = None
    CRC_INTER_AGR: Optional[int] = None
    LEASE_DOCUMENT: Optional[int] = None
    LEASE_SRNO: Optional[int] = None
    LEASE_DOCUMENT_TYPE: Optional[str] = None
    LEASE_LAST_AGREEMENT: Optional[int] = None
    LEASE_LAST_SUB_AGRNO: Optional[int] = None
    LEASE_VEH_TYPE: Optional[int] = None
    CRC_CHAUFFEUR: Optional[str] = None
    Location: Optional[int] = None
    SUB_STATUS: Optional[int] = None
    PROMOTIONAL_VEH: Optional[str] = None
    MARK_PREREADY_STAT: Optional[str] = None
    YARD_NO: Optional[int] = None
    AWXX_LAST_UPDATE_DATE: Optional[datetime] = None

def to_car_control(row: Dict[str, Any]) -> CarControl:
    # Pass-through, relying on Pydantic to coerce types
    return CarControl(**row)

# -------------------- SQLAlchemy / SQL Server --------------------
CONN_STR = (
    "mssql+pyodbc://@10.0.0.5\\carpro/LIVE"
    "?driver=ODBC+Driver+18+for+SQL+Server"
    "&trusted_connection=yes"
    "&Encrypt=yes"
    "&TrustServerCertificate=yes"
)
engine = create_engine(
    CONN_STR,
    pool_pre_ping=True,
    fast_executemany=True,
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
metadata = MetaData()

# -------------------- Table Definitions --------------------
items_table = Table(
    "Items",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(200), nullable=False),
    Column("description", String, nullable=False),
    Column("price", Numeric(18, 2), nullable=False),
    schema="dbo",
)

extras_table = Table(
    "EXTRAS",
    metadata,
    Column("EXTRAS_CODE", String(3)),
    Column("NAME", String(30)),
    Column("ENGLISH_NAME", String(15)),
    Column("EXTRA_UNIT", Integer),
    Column("EXTRA_GROUP", Integer),
    Column("VAT", Numeric(18, 6)),
    Column("VAT_CODE", String(14)),
    Column("INVENTORY", String(1)),
    Column("GL_CODE", String(20)),
    Column("GL_CODE_SL", String(20)),
    Column("INTERNATIONAL_CODE", String(8)),
    Column("ALLOW_IN_CS", Integer),
    Column("ALLOW_IN_WEB", Integer),
    Column("ALLOW_IN_CLIENT", Integer),
    Column("ALLOW_IN_PORTAL", Integer),
    Column("EXT_EXTRA_FOR", String(1)),
    Column("CALCULATE_VAT", String(1)),
    Column("INVENTORY_BY_SUBEXTRA", Integer),
    Column("SUB_EXTRA_LASTNO", Integer),
    Column("FLAT_AMOUNT_YN", String(1)),
    schema="dbo",
)

car_control_table = Table(
    "CAR_CONTROL",
    metadata,
    Column("UNIT_NO", String(10), nullable=True),
    Column("LICENSE_NO", String(10), nullable=True),
    Column("COMPANY_CODE", SmallInteger, nullable=True),
    Column("FLEET_ASSIGNMENT", String(1), nullable=True),
    Column("F_GROUP", String(5), nullable=True),
    Column("CAR_MAKE", SmallInteger, nullable=True),
    Column("MODEL", Integer, nullable=True),
    Column("COLOR", String(10), nullable=True),
    Column("CAR_STATUS", SmallInteger, nullable=True),
    Column("OWNER_COUNTRY", String(3), nullable=True),
    Column("CHECK_OUT_DATE", String(8), nullable=True),
    Column("CHECK_OUT_TIME", Integer, nullable=True),
    Column("CHECK_OUT_BRANACH", Integer, nullable=True),
    Column("CHECK_IN_DATE", String(8), nullable=True),
    Column("CHECK_IN_TIME", Integer, nullable=True),
    Column("CHECK_IN_BRANACH", Integer, nullable=True),
    Column("BRANACH", Integer, nullable=True),
    Column("COUNTRY", String(3), nullable=True),
    Column("CURRENT_ODOMETER", Integer, nullable=True),
    Column("OUT_OF_SERVICE_REAS", SmallInteger, nullable=True),
    Column("VEHICLE_TYPE", String(2), nullable=True),
    Column("PARKING_LOT_CODE", SmallInteger, nullable=True),
    Column("PARKING_SPACE", Integer, nullable=True),
    Column("SALE_CYCLE", SmallInteger, nullable=True),
    Column("LAST_DOCUMENT_TYPE", String(1), nullable=True),
    Column("LAST_DOCUMENT_NO", SAFloat, nullable=True),
    Column("LAST_SUV_AGREEMENT", SmallInteger, nullable=True),
    Column("ODOMETER_AFTER_MIN", Integer, nullable=True),
    Column("RESERVED_TO", String(12), nullable=True),
    Column("GARAGE", Integer, nullable=True),
    Column("SMOKE", String(1), nullable=True),
    Column("TELEPHONE", String(20), nullable=True),
    Column("TAXILIMO_CHAUFFEUR", String(10), nullable=True),
    Column("PRECHECKED_IN_PLACE", String(40), nullable=True),
    Column("FLEET_SUB_ASSIGNMENT", SmallInteger, nullable=True),
    Column("DEPOSIT_NOTE", SAFloat, nullable=True),
    Column("EUROPCAR_COMPANY", String(1), nullable=True),
    Column("PETROL_LEVEL", SmallInteger, nullable=True),
    Column("TRANSACTION_USER", String(15), nullable=True),
    Column("TRANSACTION_DATE", String(8), nullable=True),
    Column("TRANSACTION_TIME", Integer, nullable=True),
    Column("MORTGAGED_TO", Integer, nullable=True),
    Column("CRC_INTER_AGR", Integer, nullable=True),
    Column("LEASE_DOCUMENT", Integer, nullable=True),
    Column("LEASE_SRNO", SmallInteger, nullable=True),
    Column("LEASE_DOCUMENT_TYPE", String(1), nullable=True),
    Column("LEASE_LAST_AGREEMENT", Integer, nullable=True),
    Column("LEASE_LAST_SUB_AGRNO", SmallInteger, nullable=True),
    Column("LEASE_VEH_TYPE", SmallInteger, nullable=True),
    Column("CRC_CHAUFFEUR", String(10), nullable=True),
    Column("Location", SmallInteger, nullable=True),
    Column("SUB_STATUS", SmallInteger, nullable=True),
    Column("PROMOTIONAL_VEH", String(1), nullable=True),
    Column("MARK_PREREADY_STAT", String(1), nullable=True),
    Column("YARD_NO", Integer, nullable=True),
    Column("AWXX_LAST_UPDATE_DATE", DateTime, nullable=True),
    schema="dbo",
)

# -------------------- DB session dependency --------------------
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------- Helpers --------------------
def apply_ordering(query, table, order_by: Optional[str], default_col: str) -> Tuple[Any, Optional[str]]:
    """
    order_by format: "COLUMN" or "COLUMN:asc|desc"
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
        # If invalid column, just return query unchanged
        return query, None
    if direction not in ("asc", "desc"):
        direction = "asc"
    query = query.order_by(col.asc() if direction == "asc" else col.desc())
    return query, f"{col_name}:{direction}"

def like_or_equals(col, value: Optional[str], partial: bool):
    if value is None:
        return None
    if partial:
        return col.like(f"%{value}%")
    return col == value

# -------------------- CRUD for Items (unchanged) --------------------
@app.get("/items", response_model=List[Item])
def get_items(db: Session = Depends(get_db)):
    rows = db.execute(select(items_table)).mappings().all()
    return [to_item(dict(r)) for r in rows]

@app.get("/items/{item_id}", response_model=Item)
def get_item(item_id: int, db: Session = Depends(get_db)):
    row = db.execute(
        select(items_table).where(items_table.c.id == item_id)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Item not found")
    return to_item(dict(row))

@app.post("/items", response_model=Item, status_code=201)
def create_item(item: Item, db: Session = Depends(get_db)):
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
def update_item(item_id: int, updated_item: Item, db: Session = Depends(get_db)):
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
def delete_item(item_id: int, db: Session = Depends(get_db)):
    res = db.execute(delete(items_table).where(items_table.c.id == item_id))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    db.commit()
    return {"message": "Item deleted"}

# -------------------- Existing Extras endpoints (kept for compatibility) --------------------
@app.get("/extras", response_model=List[Extra], tags=["Extras (compat)"])
def get_extras(
    db: Session = Depends(get_db),
    EXTRAS_CODE: Optional[str] = None,
    NAME: Optional[str] = None,
):
    if not EXTRAS_CODE and not NAME:
        raise HTTPException(status_code=422, detail="Either EXTRAS_CODE or NAME must be provided")
    query = select(extras_table)
    if EXTRAS_CODE:
        query = query.where(extras_table.c.EXTRAS_CODE == EXTRAS_CODE)
    if NAME:
        query = query.where(extras_table.c.NAME == NAME)
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]

@app.get("/extras/{code}", response_model=Extra, tags=["Extras"])
def get_extra(code: str, db: Session = Depends(get_db)):
    row = db.execute(
        select(extras_table).where(extras_table.c.EXTRAS_CODE == code)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Extra not found")
    return to_extra(dict(row))

@app.post("/extras", response_model=Extra, status_code=201, tags=["Extras"])
def create_extra(extra: Extra, db: Session = Depends(get_db)):
    if not extra.EXTRAS_CODE and not extra.NAME:
        raise HTTPException(status_code=422, detail="Either EXTRAS_CODE or NAME must be provided")
    # optional conflict check if EXTRAS_CODE provided
    if extra.EXTRAS_CODE:
        exists = db.execute(
            select(extras_table.c.EXTRAS_CODE).where(extras_table.c.EXTRAS_CODE == extra.EXTRAS_CODE)
        ).scalar()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"Extra with code {extra.EXTRAS_CODE} already exists")
    db.execute(insert(extras_table).values(**extra.dict(exclude_unset=True)))
    db.commit()
    row = None
    if extra.EXTRAS_CODE:
        row = db.execute(
            select(extras_table).where(extras_table.c.EXTRAS_CODE == extra.EXTRAS_CODE)
        ).mappings().first()
    return to_extra(dict(row)) if row else extra

@app.put("/extras/{code}", response_model=Extra, tags=["Extras"])
def update_extra(code: str, extra: Extra, db: Session = Depends(get_db)):
    if not extra.dict(exclude_unset=True):
        raise HTTPException(status_code=422, detail="No fields to update")
    res = db.execute(
        update(extras_table)
        .where(extras_table.c.EXTRAS_CODE == code)
        .values(**extra.dict(exclude_unset=True))
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Extra not found")
    db.commit()
    row = db.execute(
        select(extras_table).where(extras_table.c.EXTRAS_CODE == code)
    ).mappings().first()
    return to_extra(dict(row))

@app.delete("/extras/{code}", tags=["Extras"])
def delete_extra(code: str, db: Session = Depends(get_db)):
    res = db.execute(delete(extras_table).where(extras_table.c.EXTRAS_CODE == code))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Extra not found")
    db.commit()
    return {"message": "Extra deleted"}

# -------------------- NEW: Extras List & Search --------------------
@app.get("/extras/list", response_model=List[Extra], tags=["Extras"])
def list_extras(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    order_by: Optional[str] = Query(None, description='e.g. "EXTRAS_CODE:asc" or "NAME:desc"'),
):
    query = select(extras_table).offset(offset).limit(limit)
    query, _ = apply_ordering(query, extras_table, order_by, default_col="EXTRAS_CODE")
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]

@app.get("/extras/search", response_model=List[Extra], tags=["Extras"])
def search_extras(
    db: Session = Depends(get_db),
    code: Optional[str] = Query(None, alias="EXTRAS_CODE"),
    name: Optional[str] = Query(None, alias="NAME"),
    group_: Optional[int] = Query(None, alias="EXTRA_GROUP"),
    inventory: Optional[str] = Query(None, alias="INVENTORY"),
    partial: bool = Query(True, description="Use partial matches (LIKE)"),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    order_by: Optional[str] = Query(None, description='e.g. "NAME:asc"'),
):
    query = select(extras_table)
    filters = []
    f = like_or_equals

    if code is not None:
        filters.append(f(extras_table.c.EXTRAS_CODE, code, partial))
    if name is not None:
        filters.append(f(extras_table.c.NAME, name, partial))
    if group_ is not None:
        filters.append(extras_table.c.EXTRA_GROUP == group_)
    if inventory is not None:
        filters.append(f(extras_table.c.INVENTORY, inventory, partial=False))

    for cond in filters:
        if cond is not None:
            query = query.where(cond)

    query = query.offset(offset).limit(limit)
    query, _ = apply_ordering(query, extras_table, order_by, default_col="EXTRAS_CODE")
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]

# -------------------- Existing CAR_CONTROL endpoints (kept) --------------------
@app.get("/car_control", response_model=List[CarControl], tags=["Car_Control (compat)"])
def get_car_control(
    db: Session = Depends(get_db),
    UNIT_NO: Optional[str] = None,
    LICENSE_NO: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    query = select(car_control_table)
    if UNIT_NO:
        query = query.where(car_control_table.c.UNIT_NO == UNIT_NO)
    if LICENSE_NO:
        query = query.where(car_control_table.c.LICENSE_NO == LICENSE_NO)
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]

@app.get("/car_control/{unit_no}", response_model=CarControl, tags=["Car_Control"])
def get_car_control_one(unit_no: str, db: Session = Depends(get_db)):
    row = db.execute(
        select(car_control_table).where(car_control_table.c.UNIT_NO == unit_no)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Car control row not found")
    return to_car_control(dict(row))

@app.post("/car_control", response_model=CarControl, status_code=201, tags=["Car_Control"])
def create_car_control(item: CarControl, db: Session = Depends(get_db)):
    payload = item.dict(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=422, detail="Request body is empty")
    # Optional conflict check if UNIT_NO supplied
    if "UNIT_NO" in payload and payload["UNIT_NO"]:
        exists = db.execute(
            select(car_control_table.c.UNIT_NO).where(car_control_table.c.UNIT_NO == payload["UNIT_NO"])
        ).scalar()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"UNIT_NO {payload['UNIT_NO']} already exists")
    db.execute(insert(car_control_table).values(**payload))
    db.commit()
    if "UNIT_NO" in payload:
        row = db.execute(
            select(car_control_table).where(car_control_table.c.UNIT_NO == payload["UNIT_NO"])
        ).mappings().first()
        if row:
            return to_car_control(dict(row))
    return item

@app.put("/car_control/{unit_no}", response_model=CarControl, tags=["Car_Control"])
def update_car_control(unit_no: str, item: CarControl, db: Session = Depends(get_db)):
    payload = item.dict(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=422, detail="No fields to update")
    res = db.execute(
        update(car_control_table)
        .where(car_control_table.c.UNIT_NO == unit_no)
        .values(**payload)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Car control row not found")
    db.commit()
    row = db.execute(
        select(car_control_table).where(car_control_table.c.UNIT_NO == unit_no)
    ).mappings().first()
    return to_car_control(dict(row))

@app.delete("/car_control/{unit_no}", tags=["Car_Control"])
def delete_car_control(unit_no: str, db: Session = Depends(get_db)):
    res = db.execute(delete(car_control_table).where(car_control_table.c.UNIT_NO == unit_no))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Car control row not found")
    db.commit()
    return {"message": "Car control row deleted"}

# -------------------- NEW: CAR_CONTROL List & Search --------------------
@app.get("/car_control/list", response_model=List[CarControl], tags=["Car_Control"])
def list_car_control(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    order_by: Optional[str] = Query(None, description='e.g. "UNIT_NO:asc", "CAR_STATUS:desc"'),
):
    query = select(car_control_table).offset(offset).limit(limit)
    query, _ = apply_ordering(query, car_control_table, order_by, default_col="UNIT_NO")
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]

@app.get("/car_control/search", response_model=List[CarControl], tags=["Car_Control"])
def search_car_control(
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
    order_by: Optional[str] = Query(None, description='e.g. "UNIT_NO:asc"'),
):
    query = select(car_control_table)
    filters = []

    if unit_no is not None:
        filters.append(like_or_equals(car_control_table.c.UNIT_NO, unit_no, partial))
    if license_no is not None:
        filters.append(like_or_equals(car_control_table.c.LICENSE_NO, license_no, partial))
    if car_status is not None:
        filters.append(car_control_table.c.CAR_STATUS == car_status)
    if vehicle_type is not None:
        filters.append(like_or_equals(car_control_table.c.VEHICLE_TYPE, vehicle_type, partial=False))
    if color is not None:
        filters.append(like_or_equals(car_control_table.c.COLOR, color, partial))
    if country is not None:
        filters.append(like_or_equals(car_control_table.c.COUNTRY, country, partial=False))

    for cond in filters:
        if cond is not None:
            query = query.where(cond)

    query = query.offset(offset).limit(limit)
    query, _ = apply_ordering(query, car_control_table, order_by, default_col="UNIT_NO")
    rows = db.execute(query).mappings().all()
    return [to_car_control(dict(r)) for r in rows]

@app.get("/")
def root():
    return {"message": "Bugzy's FastAPI is running!"}
