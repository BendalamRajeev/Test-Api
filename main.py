from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, text, inspect
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import pandas as pd
import json
import io
import os

# ---------- Config ----------
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
ALGORITHM = "HS256"


# ---------- App & DB ----------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update with specific frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------- User Model ----------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    mac_address = Column(String(17), unique=True, nullable=False)

Base.metadata.create_all(bind=engine)

# ---------- Auth Utils ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ---------- Schemas ----------
class SignupData(BaseModel):
    username: str
    password: str
    mac_address: str

class LoginData(BaseModel):
    username: str
    password: str
    mac_address: str

# ---------- Dependency ----------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------- Signup/Login Routes ----------
def signup(data: SignupData, db: Session = Depends(get_db)):
    # Check if the username exists
    existing_user = db.query(User).filter(User.username == data.username).first()

    if existing_user:
        # If username exists and password + MAC address match => already registered
        if verify_password(data.password, existing_user.hashed_password) and existing_user.mac_address == data.mac_address:
            raise HTTPException(status_code=400, detail="User already registered")
        # If username exists but MAC address is different
        elif existing_user.mac_address != data.mac_address:
            raise HTTPException(status_code=403, detail="User already registered on another device. Please log in using the registered device.")
        # If username exists but password doesn't match
        else:
            raise HTTPException(status_code=400, detail="Username already taken with different credentials")

    # Check if MAC address is already used by a different user
    mac_id = db.query(User).filter(User.mac_address == data.mac_address).first()
    if mac_id:
        raise HTTPException(status_code=400, detail="Device already registered with another user")

    # Register new user
    hashed_pwd = hash_password(data.password)
    new_user = User(username=data.username, hashed_password=hashed_pwd, mac_address=data.mac_address)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}


@app.post("/login")
def login(data: LoginData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.mac_address != data.mac_address:
        raise HTTPException(status_code=403, detail="User is already registered on another device. Please log in using the registered device.")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# ---------- Upload File Route ----------
@app.post("/upload/")
async def upload_user_data(files: list[UploadFile] = File(...)):
    inserted, skipped = 0, 0
    inspector = inspect(engine)
    insertable_columns = [col["name"] for col in inspector.get_columns("users") if col["name"] not in ("id",)]

    for file in files:
        try:
            if file.filename.endswith(".json"):
                content = await file.read()
                df = pd.DataFrame(json.loads(content))
            elif file.filename.endswith((".xls", ".xlsx")):
                content = await file.read()
                df = pd.read_excel(io.BytesIO(content))
            else:
                continue

            matched_cols = [col for col in df.columns if col in insertable_columns]
            df = df[matched_cols]

            with engine.begin() as conn:
                for _, row in df.iterrows():
                    try:
                        cols = ", ".join(row.index)
                        placeholders = ", ".join([f":{col}" for col in row.index])
                        stmt = text(f"INSERT INTO users ({cols}) VALUES ({placeholders})")
                        conn.execute(stmt, row.to_dict())
                        inserted += 1
                    except IntegrityError:
                        skipped += 1
        except Exception as e:
            return {"error": f"Failed to process {file.filename}: {str(e)}"}

    return {
        "message": "Upload completed",
        "rows_inserted": inserted,
        "rows_skipped": skipped
    }

# ---------- Download Users Route ----------
@app.get("/download/")
def download_users():
    try:
        inspector = inspect(engine)
        columns = [col["name"] for col in inspector.get_columns("users")]
        column_str = ", ".join(columns)

        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT {column_str} FROM users"))
            rows = [dict(row._mapping) for row in result.fetchall()]

        return JSONResponse(content=rows)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
