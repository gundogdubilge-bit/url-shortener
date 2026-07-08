import os
import random
import secrets
import smtplib
import string
import io
import qrcode
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import text
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from typing import Optional

from database import get_db, create_tables, URLRecord, User, LoginAttempt, ClickLog, SessionLocal, engine

app = FastAPI(title="ACI1878 Link Kısaltıcı")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "aci1878-gizli-anahtar-2024"),
    max_age=86400,
)
templates = Jinja2Templates(directory="templates")

BASE_URL = os.environ.get("BASE_URL", "https://aci1878.site")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

PENDING_2FA = {}
OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def log_attempt(db: Session, email: str, success: bool, reason: str, request: Request):
    db.add(LoginAttempt(
        email=email,
        success=success,
        reason=reason,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:255],
    ))
    db.commit()


def send_otp_email(to_email: str, code: str) -> bool:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        return False
    try:
        msg = MIMEText(f"ACI1878 Link Kısaltıcı giriş doğrulama kodunuz: {code}\n\nBu kod {OTP_TTL_MINUTES} dakika içinde geçerliliğini yitirecektir.")
        msg["Subject"] = "ACI1878 Giriş Doğrulama Kodu"
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
        return True
    except Exception:
        return False


# ── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    create_tables()
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE urls ADD COLUMN created_by TEXT"))
            conn.commit()
        except Exception:
            conn.rollback()

    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN last_2fa_at TIMESTAMP"))
            conn.commit()
        except Exception:
            conn.rollback()
    db = SessionLocal()
    if not db.query(User).first():
        admin = User(
            email="admin@aci.k12.tr",
            full_name="Sistem Yöneticisi",
            password_hash=pwd_context.hash("aci1878"),
            is_admin=True,
        )
        db.add(admin)
        db.commit()
    db.close()


# ── Auth helpers ──────────────────────────────────────────────────────────────

def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    email = request.session.get("user_email")
    if not email:
        return None
    return db.query(User).filter(User.email == email, User.is_active == True).first()


def require_login(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return user


def generate_short_code(length: int = 6) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


# ── Login / Logout ────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    user_email = request.session.get("user_email")
    if user_email:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email_norm = email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).first()
    if not user or not user.is_active or not pwd_context.verify(password, user.password_hash):
        log_attempt(db, email_norm, False, "invalid_credentials", request)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": True
        })

    today = datetime.utcnow().date()
    if user.last_2fa_at and user.last_2fa_at.date() == today:
        log_attempt(db, user.email, True, "same_day_2fa_skip", request)
        request.session["user_email"] = user.email
        return RedirectResponse(url="/", status_code=303)

    code = f"{secrets.randbelow(1000000):06d}"
    PENDING_2FA[user.email] = {
        "code": code,
        "expires": datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES),
        "attempts": 0,
    }
    if not send_otp_email(user.email, code):
        log_attempt(db, user.email, False, "email_send_failed", request)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": True,
            "smtp_error": True,
        })
    log_attempt(db, user.email, True, "password_ok_pending_2fa", request)
    return templates.TemplateResponse("verify_code.html", {"request": request, "email": user.email})


@app.post("/login/verify-code", response_class=HTMLResponse)
def verify_code(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    pending = PENDING_2FA.get(email)
    if not pending or datetime.utcnow() > pending["expires"]:
        PENDING_2FA.pop(email, None)
        log_attempt(db, email, False, "code_expired", request)
        return templates.TemplateResponse("login.html", {"request": request, "error": True, "code_expired": True})

    if code.strip() != pending["code"]:
        pending["attempts"] += 1
        if pending["attempts"] >= OTP_MAX_ATTEMPTS:
            PENDING_2FA.pop(email, None)
            log_attempt(db, email, False, "2fa_max_attempts", request)
            return templates.TemplateResponse("login.html", {"request": request, "error": True, "code_expired": True})
        log_attempt(db, email, False, "2fa_wrong_code", request)
        return templates.TemplateResponse("verify_code.html", {
            "request": request, "email": email, "error": True,
            "attempts_left": OTP_MAX_ATTEMPTS - pending["attempts"],
        })

    PENDING_2FA.pop(email, None)
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active:
        log_attempt(db, email, False, "user_inactive", request)
        return templates.TemplateResponse("login.html", {"request": request, "error": True})

    user.last_2fa_at = datetime.utcnow()
    db.commit()
    log_attempt(db, email, True, "2fa_success", request)
    request.session["user_email"] = user.email
    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


# ── Ana Sayfa ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if user.is_admin:
        urls = db.query(URLRecord).order_by(URLRecord.created_at.desc()).limit(50).all()
        all_users = db.query(User).order_by(User.created_at.desc()).all()
        login_attempts = db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all()
        click_logs = db.query(ClickLog).order_by(ClickLog.created_at.desc()).limit(100).all()
    else:
        urls = db.query(URLRecord).filter(URLRecord.created_by == user.email).order_by(URLRecord.created_at.desc()).all()
        all_users = []
        login_attempts = []
        click_logs = []

    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "urls": urls,
        "all_users": all_users,
        "login_attempts": login_attempts,
        "click_logs": click_logs,
        "base_url": BASE_URL,
        "now": datetime.utcnow(),
    })


# ── Link İşlemleri ─────────────────────────────────────────────────────────────

@app.post("/web/shorten", response_class=HTMLResponse)
def web_shorten(
    request: Request,
    original_url: str = Form(...),
    custom_alias: str = Form(""),
    expires_in_days: str = Form(""),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    alias = custom_alias.strip() if custom_alias.strip() else generate_short_code()

    if db.query(URLRecord).filter(URLRecord.short_code == alias).first():
        urls = db.query(URLRecord).filter(URLRecord.created_by == user.email).order_by(URLRecord.created_at.desc()).all() if not user.is_admin else db.query(URLRecord).order_by(URLRecord.created_at.desc()).limit(50).all()
        return templates.TemplateResponse("index.html", {
            "request": request, "user": user, "urls": urls,
            "all_users": db.query(User).order_by(User.created_at.desc()).all() if user.is_admin else [],
            "login_attempts": db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all() if user.is_admin else [],
            "click_logs": db.query(ClickLog).order_by(ClickLog.created_at.desc()).limit(100).all() if user.is_admin else [],
            "base_url": BASE_URL, "now": datetime.utcnow(),
            "error": f"'{alias}' alias'i zaten kullanımda."
        })

    expires_at = None
    if expires_in_days.strip():
        try:
            expires_at = datetime.utcnow() + timedelta(days=int(expires_in_days))
        except ValueError:
            pass

    record = URLRecord(
        short_code=alias,
        original_url=original_url,
        expires_at=expires_at,
        created_by=user.email,
    )
    db.add(record)
    db.commit()

    urls = db.query(URLRecord).filter(URLRecord.created_by == user.email).order_by(URLRecord.created_at.desc()).all() if not user.is_admin else db.query(URLRecord).order_by(URLRecord.created_at.desc()).limit(50).all()
    return templates.TemplateResponse("index.html", {
        "request": request, "user": user, "urls": urls,
        "all_users": db.query(User).order_by(User.created_at.desc()).all() if user.is_admin else [],
        "login_attempts": db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all() if user.is_admin else [],
        "click_logs": db.query(ClickLog).order_by(ClickLog.created_at.desc()).limit(100).all() if user.is_admin else [],
        "base_url": BASE_URL, "now": datetime.utcnow(),
        "success": f"{BASE_URL}/{alias}"
    })


@app.post("/web/delete/{short_code}")
def web_delete(short_code: str, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    record = db.query(URLRecord).filter(URLRecord.short_code == short_code).first()
    if record and (user.is_admin or record.created_by == user.email):
        db.delete(record)
        db.commit()
    return RedirectResponse(url="/", status_code=303)


# ── Kullanıcı Yönetimi (Admin) ─────────────────────────────────────────────────

@app.post("/admin/users/add", response_class=HTMLResponse)
def admin_add_user(
    request: Request,
    email: str = Form(...),
    full_name: str = Form(""),
    password: str = Form(...),
    is_admin: str = Form("off"),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        return RedirectResponse(url="/", status_code=303)

    email = email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        urls = db.query(URLRecord).order_by(URLRecord.created_at.desc()).limit(50).all()
        return templates.TemplateResponse("index.html", {
            "request": request, "user": user, "urls": urls,
            "all_users": db.query(User).order_by(User.created_at.desc()).all(),
            "login_attempts": db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all(),
            "click_logs": db.query(ClickLog).order_by(ClickLog.created_at.desc()).limit(100).all(),
            "base_url": BASE_URL, "now": datetime.utcnow(),
            "user_error": f"'{email}' zaten kayıtlı."
        })

    new_user = User(
        email=email,
        full_name=full_name.strip(),
        password_hash=pwd_context.hash(password),
        is_admin=(is_admin == "on"),
    )
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.post("/admin/users/delete/{user_id}")
def admin_delete_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        return RedirectResponse(url="/", status_code=303)
    target = db.query(User).filter(User.id == user_id).first()
    if target and target.email != user.email:
        db.delete(target)
        db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.post("/admin/users/toggle/{user_id}")
def admin_toggle_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        return RedirectResponse(url="/", status_code=303)
    target = db.query(User).filter(User.id == user_id).first()
    if target and target.email != user.email:
        target.is_active = not target.is_active
        db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.post("/admin/users/reset-password/{user_id}")
def admin_reset_password(
    user_id: int,
    request: Request,
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        return RedirectResponse(url="/", status_code=303)
    target = db.query(User).filter(User.id == user_id).first()
    if target:
        target.password_hash = pwd_context.hash(new_password)
        db.commit()
    return RedirectResponse(url="/?tab=users&msg=reset_ok", status_code=303)


# ── Kullanıcı Şifre Değiştirme ────────────────────────────────────────────────

@app.post("/profile/change-password", response_class=HTMLResponse)
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    def _reload(pw_error=None, pw_success=None):
        urls = db.query(URLRecord).filter(URLRecord.created_by == user.email).order_by(URLRecord.created_at.desc()).all() if not user.is_admin else db.query(URLRecord).order_by(URLRecord.created_at.desc()).limit(50).all()
        return templates.TemplateResponse("index.html", {
            "request": request, "user": user, "urls": urls,
            "all_users": db.query(User).order_by(User.created_at.desc()).all() if user.is_admin else [],
            "login_attempts": db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all() if user.is_admin else [],
            "click_logs": db.query(ClickLog).order_by(ClickLog.created_at.desc()).limit(100).all() if user.is_admin else [],
            "base_url": BASE_URL, "now": datetime.utcnow(),
            "pw_error": pw_error, "pw_success": pw_success,
            "open_pw_modal": True,
        })

    if not pwd_context.verify(current_password, user.password_hash):
        return _reload(pw_error="Mevcut şifre hatalı.")

    if len(new_password) < 6:
        return _reload(pw_error="Yeni şifre en az 6 karakter olmalıdır.")

    user.password_hash = pwd_context.hash(new_password)
    db.commit()
    return _reload(pw_success="Şifreniz başarıyla değiştirildi.")


# ── QR & Yönlendirme ──────────────────────────────────────────────────────────

@app.get("/qr/{short_code}")
def get_qr(short_code: str, db: Session = Depends(get_db)):
    record = db.query(URLRecord).filter(URLRecord.short_code == short_code).first()
    if not record:
        raise HTTPException(status_code=404, detail="Link bulunamadı.")
    img = qrcode.make(f"{BASE_URL}/{short_code}")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/{short_code}")
def redirect_url(short_code: str, request: Request, db: Session = Depends(get_db)):
    if short_code in ("login", "logout", "favicon.ico"):
        raise HTTPException(status_code=404)
    record = db.query(URLRecord).filter(URLRecord.short_code == short_code).first()
    if not record:
        raise HTTPException(status_code=404, detail="Link bulunamadı.")
    if not record.is_active:
        raise HTTPException(status_code=410, detail="Bu link aktif değil.")
    if record.expires_at and datetime.utcnow() > record.expires_at:
        record.is_active = False
        db.commit()
        raise HTTPException(status_code=410, detail="Bu linkin süresi dolmuş.")
    record.click_count += 1
    db.add(ClickLog(
        short_code=short_code,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:255],
    ))
    db.commit()
    return RedirectResponse(url=record.original_url)
