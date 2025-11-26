from fastapi import FastAPI, Depends, HTTPException, Security, Form
from fastapi.security import (
    APIKeyHeader,
    OAuth2PasswordBearer,
    HTTPBearer,
    HTTPBasic,
    HTTPBasicCredentials
)
from fastapi.security.api_key import APIKey
from fastapi.responses import RedirectResponse
from typing import Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

# =====================
# CONFIG
# =====================
API_KEY = "test-api-key"
API_KEY_NAME = "X-API-Key"
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$lq9VWtR23d3/xRdG9cMyRu8G2m058eTE155siSp74uCWqS.Mej09W"  # bcrypt("password")
    }
}

# Use bcrypt for now; for serverless Argon2 is also fine
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =====================
# FASTAPI INIT
# =====================
app = FastAPI(
    title="AI Hub Auth API",
    description="Test API for AI Hub project with different authentication methods",
    version="1.0.0"
)

# =====================
# CORS (optional)
# =====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================
# SECURITY SCHEMES
# =====================
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
bearer_scheme = HTTPBearer()
basic_scheme = HTTPBasic()

# =====================
# PROJECT DATA
# =====================
PROJECT_INFO = {
    "project_name": "AI Hub",
    "manager": "Gowtham",
    "dev_team": [
        {"name": "Mohammed Rishal", "role": "Full stack Developer"},
        {"name": "Richu", "role": "Front Developer & Prompt Engineer"},
        {"name": "Muneeb", "role": "Full stack Developer"},
        {"name": "Zaheer", "role": "ML Engineer"},
        {"name": "Harsh Vardhan", "role": "AI/ML Engineer"},
        {"name": "Afsal", "role": "ML Engineer"},
        {"name": "Gnanasekaran Perumal", "role": "Back-end Developer"}
    ],
    "testing_team": [
        {"name": "Somashekar N", "role": "Manual & Automation Test Engineer, Prompt Engineer"},
        {"name": "Swathi", "role": "Manual & Automation Test Engineer, Prompt Engineer"}
    ],
    "description": "AI Hub on Neutrinos is a framework for integrating AI/ML into apps with NLP, GenAI, analytics, and automation.",
    "features": [
        "Ready-to-use AI Models",
        "Custom Model Integration",
        "API-First AI as a Service",
        "Workflow Automation",
        "Scalability for Enterprises"
    ],
    "modules": ["Dashboard", "Prediction", "Extraction", "Tokens", "Assistant", "Knowledge", "Audit Logs", "Deployment"]
}

# =====================
# AUTH HELPERS
# =====================
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_jwt_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == API_KEY:
        return api_key
    raise HTTPException(status_code=403, detail="Invalid API Key")

async def get_oauth2_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_jwt_token(token)
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid OAuth2 token")

async def get_bearer_token(credentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = decode_jwt_token(token)
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid Bearer token")

async def get_current_user(credentials: HTTPBasicCredentials = Depends(basic_scheme)):
    username = credentials.username
    password = credentials.password
    user = fake_users_db.get(username)
    if user and verify_password(password, user["hashed_password"]):
        return username
    raise HTTPException(status_code=401, detail="Invalid Basic Auth credentials")

# =====================
# ROUTES
# =====================

# 1. No Auth
@app.get("/public", summary="No Auth - Get AI Hub Info")
def public_route() -> Dict:
    return {
        "auth": "none",
        "message": "Publicly accessible AI Hub details",
        "data": PROJECT_INFO
    }

# 2. API Key
@app.get("/apikey-protected", summary="API Key Auth - Get AI Hub Info")
def api_key_route(api_key: APIKey = Depends(get_api_key)):
    return {
        "auth": "api_key",
        "message": "You accessed AI Hub data with an API Key",
        "data": PROJECT_INFO
    }

# 3. OAuth2
@app.post("/token", summary="Get OAuth2 Token")
def login_oauth2(username: str = Form(...), password: str = Form(...)):
    user = fake_users_db.get(username)
    if user and verify_password(password, user["hashed_password"]):
        token = create_jwt_token({"sub": username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.get("/oauth2-protected", summary="OAuth2 Auth - Get AI Hub Info")
def oauth2_route(token_data: dict = Depends(get_oauth2_token)):
    return {
        "auth": "oauth2",
        "user": token_data.get("sub"),
        "message": "You accessed AI Hub data with OAuth2",
        "data": PROJECT_INFO
    }

# 4. Bearer
@app.get("/bearer-protected", summary="Bearer Auth - Get AI Hub Info")
def bearer_route(token_data: dict = Depends(get_bearer_token)):
    return {
        "auth": "bearer",
        "user": token_data.get("sub"),
        "message": "You accessed AI Hub data with Bearer token",
        "data": PROJECT_INFO
    }

# 5. Basic Auth
@app.get("/basic-protected", summary="Basic Auth - Get AI Hub Info")
def basic_route(username: str = Depends(get_current_user)):
    return {
        "auth": "basic",
        "user": username,
        "message": f"Hello {username}, you accessed AI Hub data with Basic Auth",
        "data": PROJECT_INFO
    }

# 6. Redirect Example
# @app.get("/redirect", summary="Redirect to Webhook")
# def redirect_to_webhook():
#     return RedirectResponse(url="https://webhook.site/6effb542-5424-4049-a39f-6d879cbca244")

# =====================
# Mangum handler for Vercel
# =====================
handler = Mangum(app)
