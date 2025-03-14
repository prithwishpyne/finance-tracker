from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from typing import Optional, List
from datetime import datetime, timedelta, date
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from supabase import create_client, Client
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase configuration
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(supabase_url, supabase_key)

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = "jHXLQVrOt/vVzhn1eDJSgJanbus779DiMS8r/SWVjn9gMmNNWhuoVrtGV1xszMhhaURpJgzSS+mL1Lscaw477Q=="
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Pydantic models
class UserCreate(BaseModel):
    username: str
    password: str
    name: str

class UserInDB(BaseModel):
    username: str
    password: str
    name: str

class Token(BaseModel):
    access_token: str
    token_type: str
    name: str

class UserUpdate(BaseModel):
    name: str

class TransactionCreate(BaseModel):
    transaction_type: str
    transaction_category: str
    amount: int
    description: str
    date: date

class Transaction(TransactionCreate):
    id: int

class AssetLiabilityCreate(BaseModel):
    category: str
    type: str
    amount: int
    description: str
    date: date

class AssetLiability(AssetLiabilityCreate):
    id: int


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/register", response_model=dict)
async def register(user: UserCreate):
    # Check if user already exists
    user_query = supabase.table("users").select("*").eq("username", user.username).execute()
    if user_query.data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address already registered, Please Login"
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    new_user = {
        "username": user.username,
        "password": hashed_password,
        "name": user.name
    }
    
    try:
        result = supabase.table("users").insert(new_user).execute()
        return {"message": "Registration successful"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during registration: {str(e)}"
        )

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Get user from database
    user_query = supabase.table("users").select("*").eq("username", form_data.username).execute()
    if not user_query.data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    user = UserInDB(**user_query.data[0])
    
    # Verify password
    # if not verify_password(form_data.password):
    if not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer", "name": user.name}

@app.post("/oauth/google", response_model=dict)
async def handle_google_oauth(user_data: dict):
    try:
        print("User_data", user_data)
        # Check if user already exists
        user_query = supabase.table("users").select("*").eq("username", user_data["email"]).execute()
        
        if not user_query.data:
            # Create new user
            new_user = {
                "username": user_data["email"],
                "name": user_data.get("name", ""),
                "oauth_provider": "google"
            }
            result = supabase.table("users").insert(new_user).execute()
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_data["email"]}, expires_delta=access_token_expires
        )
        
        if user_query.data:
            return {"access_token": access_token, "token_type": "bearer", "name": user_query.data[0]["name"]}
        return {"access_token": access_token, "token_type": "bearer", "name": user_data.get("name", "")}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during Google OAuth: {str(e)}"
        )

# JWT token verification
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user_query = supabase.table("users").select("*").eq("username", username).execute()
    if not user_query.data:
        raise credentials_exception
    return {"username": username, "id": user_query.data[0]["id"]}

# New endpoint to update user name
@app.put("/users/update-name", response_model=dict)
async def update_user_name(user_update: UserUpdate, current_user: dict = Depends(get_current_user)):
    try:
        # Update user name in database
        result = supabase.table("users").update({"name": user_update.name}).eq("id", current_user["id"]).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {"message": "Name updated successfully", "name": user_update.name}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while updating the name: {str(e)}"
        )

@app.post("/transactions/", response_model=Transaction)
async def create_transaction(transaction: TransactionCreate, current_user: dict = Depends(get_current_user)):
    try:
        # print("Entered create_transaction")
        transaction_data = transaction.dict()
        transaction_data["user_id"] = current_user["id"]
        # Ensure amount is an integer
        transaction_data["amount"] = int(transaction_data["amount"])
        # Convert date to ISO format string for database storage
        transaction_data["date"] = transaction_data["date"].isoformat()
        result = supabase.table("transactions").insert(transaction_data).execute()
        # Convert date string back to date object in response
        response_data = {**result.data[0]}
        response_data["date"] = date.fromisoformat(response_data["date"])
        return response_data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while creating the transaction: {str(e)}"
        )

@app.get("/transactions/", response_model=List[Transaction])
async def get_transactions(current_user: dict = Depends(get_current_user)):
    try:
        # print("Entered get_transaction")
        result = supabase.table("transactions").select("*").eq("user_id", current_user["id"]).execute()
        # Convert date strings to date objects in response
        for transaction in result.data:
            transaction["date"] = date.fromisoformat(transaction["date"])
        return result.data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while fetching transactions: {str(e)}"
        )

@app.delete("/transactions/{transaction_id}", response_model=dict)
async def delete_transaction(transaction_id: int, current_user: dict = Depends(get_current_user)):
    try:
        # Check if transaction exists and belongs to current user
        transaction_query = supabase.table("transactions").select("*").eq("id", transaction_id).eq("user_id", current_user["id"]).execute()
        if not transaction_query.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transaction not found or you don't have permission to delete it"
            )
        
        # Delete the transaction
        result = supabase.table("transactions").delete().eq("id", transaction_id).execute()
        return {"message": "Transaction deleted successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while deleting the transaction: {str(e)}"
        )

@app.post("/assets-liabilities/", response_model=AssetLiability)
async def create_asset_liability(asset_liability: AssetLiabilityCreate, current_user: dict = Depends(get_current_user)):
    try:
        asset_liability_data = asset_liability.dict()
        asset_liability_data["user_id"] = current_user["id"]
        asset_liability_data["amount"] = int(asset_liability_data["amount"])
        asset_liability_data["date"] = asset_liability_data["date"].isoformat()
        
        result = supabase.table("assets_liabilities").insert(asset_liability_data).execute()
        
        response_data = {**result.data[0]}
        response_data["date"] = date.fromisoformat(response_data["date"])
        return response_data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while creating the asset/liability: {str(e)}"
        )

@app.get("/assets-liabilities/", response_model=List[AssetLiability])
async def get_assets_liabilities(current_user: dict = Depends(get_current_user)):
    try:
        result = supabase.table("assets_liabilities").select("*").eq("user_id", current_user["id"]).execute()
        for item in result.data:
            item["date"] = date.fromisoformat(item["date"])
        return result.data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while fetching assets and liabilities: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)