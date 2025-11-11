import os
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import FastAPI, Request, status, Depends, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, constr, ValidationError
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_429_TOO_MANY_REQUESTS
from starlette.responses import Response

import bcrypt
import psycopg2
import redis

# --- Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")
AUDIT_LOG_ENCRYPTION_KEY = os.getenv("AUDIT_LOG_ENCRYPTION_KEY")  # AES-256 key, stored in Vault/KMS
EMAIL_SENDER_ADDRESS = os.getenv("EMAIL_SENDER_ADDRESS")
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 3600  # seconds (1 hour)
PASSWORD_MIN_LENGTH = 12

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
)
logger = logging.getLogger("secure_registration")

# --- FastAPI App ---
app = FastAPI(
    title="Secure User Registration Workflow",
    description="Secure, auditable user registration API.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# --- CORS (adjust origins as needed) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- OAuth2 (for admin endpoints, not used in registration) ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Database Connection ---
def get_db_conn():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

# --- Redis Connection ---
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# --- Models ---
class RegistrationRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=PASSWORD_MIN_LENGTH, max_length=128)

class RegistrationResponse(BaseModel):
    message: str

# --- Utility Functions ---
def mask_email(email: str) -> str:
    """Mask email for audit logs (e.g., j***@d***.com)"""
    try:
        local, domain = email.split("@")
        masked_local = local[0] + "***"
        masked_domain = domain[0] + "***" + domain[domain.find('.'):]
        return f"{masked_local}@{masked_domain}"
    except Exception:
        return "***"

def password_strength(password: str) -> bool:
    """Check password strength: min 12 chars, upper, lower, digit, special."""
    import re
    if len(password) < PASSWORD_MIN_LENGTH:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

def hash_password(password: str) -> str:
    """Hash password securely using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def encrypt_audit_log(data: Dict[str, Any]) -> bytes:
    """Encrypt audit log entry using AES-256 (key from Vault/KMS)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import json
    import base64

    key = AUDIT_LOG_ENCRYPTION_KEY.encode('utf-8')
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    plaintext = json.dumps(data).encode('utf-8')
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext)

def send_confirmation_email(email: str):
    """Send confirmation email asynchronously (stub for Celery integration)."""
    # In production, enqueue Celery task here
    logger.info(f"Confirmation email sent to {mask_email(email)}")
    # TODO: Integrate with actual email service

def log_audit_entry(entry: Dict[str, Any]):
    """Log audit entry asynchronously (stub for Celery integration)."""
    # In production, enqueue Celery task here
    encrypted_entry = encrypt_audit_log(entry)
    # Store in DB (append-only, immutable)
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (id, entry, created_at) VALUES (%s, %s, %s)",
                (str(uuid.uuid4()), encrypted_entry, datetime.utcnow())
            )
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")

def is_email_unique(email: str) -> bool:
    """Check if email is unique in the user table."""
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users WHERE email = %s", (email,))
            count = cur.fetchone()[0]
        conn.close()
        return count == 0
    except Exception as e:
        logger.error(f"DB error during email uniqueness check: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

def rate_limit_key(ip: str) -> str:
    return f"reg_attempts:{ip}"

def increment_rate_limit(ip: str) -> int:
    """Increment rate limit counter for IP, return current count."""
    key = rate_limit_key(ip)
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, RATE_LIMIT_WINDOW)
    return count

def get_rate_limit_count(ip: str) -> int:
    key = rate_limit_key(ip)
    count = redis_client.get(key)
    return int(count) if count else 0

def purge_old_registrations():
    """Purge failed/incomplete registrations older than 30 days."""
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM registration_attempts WHERE status != 'completed' AND created_at < %s",
                (datetime.utcnow() - timedelta(days=30),)
            )
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to purge old registrations: {e}")

def archive_audit_logs():
    """Archive audit logs older than 2 years (encrypted at rest)."""
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE audit_log SET archived = TRUE WHERE created_at < %s",
                (datetime.utcnow() - timedelta(days=730),)
            )
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to archive audit logs: {e}")

# --- Registration Endpoint ---
@app.post("/register", response_model=RegistrationResponse, status_code=HTTP_201_CREATED)
async def register(
    request: Request,
    reg: RegistrationRequest,
    background_tasks: BackgroundTasks
):
    ip = request.client.host
    correlation_id = str(uuid.uuid4())

    # Rate limiting
    attempts = increment_rate_limit(ip)
    if attempts > RATE_LIMIT_ATTEMPTS:
        entry = {
            "event": "registration_blocked",
            "email": mask_email(reg.email),
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "correlation_id": correlation_id,
            "reason": "rate_limit_exceeded"
        }
        background_tasks.add_task(log_audit_entry, entry)
        logger.warning(f"[{correlation_id}] Rate limit exceeded for IP {ip}")
        raise HTTPException(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later."
        )

    # Input validation
    if not password_strength(reg.password):
        entry = {
            "event": "registration_failed",
            "email": mask_email(reg.email),
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "correlation_id": correlation_id,
            "reason": "weak_password"
        }
        background_tasks.add_task(log_audit_entry, entry)
        logger.info(f"[{correlation_id}] Weak password attempt for {mask_email(reg.email)}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Password does not meet strength requirements."
        )

    # Email uniqueness
    if not is_email_unique(reg.email):
        entry = {
            "event": "registration_failed",
            "email": mask_email(reg.email),
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "correlation_id": correlation_id,
            "reason": "duplicate_email"
        }
        background_tasks.add_task(log_audit_entry, entry)
        logger.info(f"[{correlation_id}] Duplicate email registration attempt: {mask_email(reg.email)}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Email is already registered."
        )

    # Hash password
    hashed_password = hash_password(reg.password)

    # Store user (minimal profile, encrypted at rest)
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (id, email, password_hash, created_at) VALUES (%s, %s, %s, %s)",
                (str(uuid.uuid4()), reg.email, hashed_password, datetime.utcnow())
            )
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"[{correlation_id}] DB error during registration: {e}")
        entry = {
            "event": "registration_failed",
            "email": mask_email(reg.email),
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "correlation_id": correlation_id,
            "reason": "db_error"
        }
        background_tasks.add_task(log_audit_entry, entry)
        raise HTTPException(
            status_code=500,
            detail="Internal server error."
        )

    # Audit log entry (immutable, masked, encrypted)
    entry = {
        "event": "registration_success",
        "email": mask_email(reg.email),
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "correlation_id": correlation_id
    }
    background_tasks.add_task(log_audit_entry, entry)

    # Send confirmation email asynchronously
    background_tasks.add_task(send_confirmation_email, reg.email)

    logger.info(f"[{correlation_id}] Registration successful for {mask_email(reg.email)}")

    return RegistrationResponse(message="Registration successful. Please check your email to confirm your account.")

# --- Health Check Endpoint ---
@app.get("/health", summary="Health check", tags=["system"])
async def health():
    """Health check endpoint for readiness/liveness probes."""
    try:
        # DB check
        conn = get_db_conn()
        conn.close()
        # Redis check
        redis_client.ping()
        return JSONResponse({"status": "ok"}, status_code=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse({"status": "error", "details": str(e)}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

# --- Exports ---
# FastAPI app instance is exported for ASGI server (e.g., uvicorn)
# Endpoints: /register, /health

# --- Startup Tasks ---
@app.on_event("startup")
def on_startup():
    logger.info("Secure Registration API starting up.")
    # Optionally schedule periodic purging/archiving tasks via Celery/cron
    # purge_old_registrations()
    # archive_audit_logs()

@app.on_event("shutdown")
def on_shutdown():
    logger.info("Secure Registration API shutting down.")