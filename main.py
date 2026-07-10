import os
import random
import string
import io
import subprocess
import qrcode
import urllib.parse
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

LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_MINUTES = 15


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_click_groups(db: Session, limit: int = 500):
    click_logs = db.query(ClickLog).order_by(ClickLog.created_at.desc()).limit(limit).all()
    groups = {}
    order = []
    for c in click_logs:
        if c.short_code not in groups:
            groups[c.short_code] = []
            order.append(c.short_code)
        groups[c.short_code].append(c)
    return [{"short_code": code, "clicks": groups[code]} for code in order]


def log_attempt(db: Session, email: str, success: bool, reason: str, request: Request):
    db.add(LoginAttempt(
        email=email,
        success=success,
        reason=reason,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:255],
    ))
    db.commit()


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

    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE urls ADD COLUMN require_email BOOLEAN DEFAULT FALSE"))
            conn.commit()
        except Exception:
            conn.rollback()

    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE click_logs ADD COLUMN visitor_email TEXT"))
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
    return templates.TemplateResponse(request, "login.html")


@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email_norm = email.strip().lower()

    window_start = datetime.utcnow() - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)
    recent_failures = db.query(LoginAttempt).filter(
        LoginAttempt.email == email_norm,
        LoginAttempt.success == False,
        LoginAttempt.created_at >= window_start,
    ).count()
    if recent_failures >= LOCKOUT_THRESHOLD:
        log_attempt(db, email_norm, False, "locked_out", request)
        return templates.TemplateResponse(request, "login.html", {
            "error": True,
            "locked_out": True,
        })

    user = db.query(User).filter(User.email == email_norm).first()
    if not user or not user.is_active or not pwd_context.verify(password, user.password_hash):
        log_attempt(db, email_norm, False, "invalid_credentials", request)
        return templates.TemplateResponse(request, "login.html", {
            "error": True
        })

    log_attempt(db, user.email, True, "login_success", request)
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
        click_groups = get_click_groups(db)
    else:
        urls = db.query(URLRecord).filter(URLRecord.created_by == user.email).order_by(URLRecord.created_at.desc()).all()
        all_users = []
        login_attempts = []
        click_groups = []

    return templates.TemplateResponse(request, "index.html", {
        "user": user,
        "urls": urls,
        "all_users": all_users,
        "login_attempts": login_attempts,
        "click_groups": click_groups,
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
    require_email: str = Form("off"),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    alias = custom_alias.strip() if custom_alias.strip() else generate_short_code()

    if db.query(URLRecord).filter(URLRecord.short_code == alias).first():
        urls = db.query(URLRecord).filter(URLRecord.created_by == user.email).order_by(URLRecord.created_at.desc()).all() if not user.is_admin else db.query(URLRecord).order_by(URLRecord.created_at.desc()).limit(50).all()
        return templates.TemplateResponse(request, "index.html", {
            "user": user, "urls": urls,
            "all_users": db.query(User).order_by(User.created_at.desc()).all() if user.is_admin else [],
            "login_attempts": db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all() if user.is_admin else [],
            "click_groups": get_click_groups(db) if user.is_admin else [],
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
        require_email=(require_email == "on"),
    )
    db.add(record)
    db.commit()

    urls = db.query(URLRecord).filter(URLRecord.created_by == user.email).order_by(URLRecord.created_at.desc()).all() if not user.is_admin else db.query(URLRecord).order_by(URLRecord.created_at.desc()).limit(50).all()
    return templates.TemplateResponse(request, "index.html", {
        "user": user, "urls": urls,
        "all_users": db.query(User).order_by(User.created_at.desc()).all() if user.is_admin else [],
        "login_attempts": db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all() if user.is_admin else [],
        "click_groups": get_click_groups(db) if user.is_admin else [],
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
        return templates.TemplateResponse(request, "index.html", {
            "user": user, "urls": urls,
            "all_users": db.query(User).order_by(User.created_at.desc()).all(),
            "login_attempts": db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all(),
            "click_groups": get_click_groups(db),
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
        return templates.TemplateResponse(request, "index.html", {
            "user": user, "urls": urls,
            "all_users": db.query(User).order_by(User.created_at.desc()).all() if user.is_admin else [],
            "login_attempts": db.query(LoginAttempt).order_by(LoginAttempt.created_at.desc()).limit(100).all() if user.is_admin else [],
            "click_groups": get_click_groups(db) if user.is_admin else [],
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


def _get_valid_record(short_code: str, db: Session) -> URLRecord:
    record = db.query(URLRecord).filter(URLRecord.short_code == short_code).first()
    if not record:
        raise HTTPException(status_code=404, detail="Link bulunamadı.")
    if not record.is_active:
        raise HTTPException(status_code=410, detail="Bu link aktif değil.")
    if record.expires_at and datetime.utcnow() > record.expires_at:
        record.is_active = False
        db.commit()
        raise HTTPException(status_code=410, detail="Bu linkin süresi dolmuş.")
    return record


def _log_click_and_redirect(record: URLRecord, request: Request, db: Session, visitor_email: Optional[str] = None):
    record.click_count += 1
    db.add(ClickLog(
        short_code=record.short_code,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:255],
        visitor_email=visitor_email,
    ))
    db.commit()
    return RedirectResponse(url=record.original_url, status_code=303)


def _visited_cookie_name(short_code: str) -> str:
    return f"visited_{short_code}"


@app.get("/{short_code}")
def redirect_url(short_code: str, request: Request, db: Session = Depends(get_db)):
    if short_code in ("login", "logout", "favicon.ico"):
        raise HTTPException(status_code=404)
    record = _get_valid_record(short_code, db)
    if record.require_email:
        cookie_val = request.cookies.get(_visited_cookie_name(short_code))
        if cookie_val:
            return _log_click_and_redirect(record, request, db, visitor_email=urllib.parse.unquote(cookie_val))
        return templates.TemplateResponse(request, "confirm.html", {"short_code": short_code})
    return _log_click_and_redirect(record, request, db)


@app.post("/{short_code}")
def redirect_url_confirm(short_code: str, request: Request, visitor_email: str = Form(...), db: Session = Depends(get_db)):
    record = _get_valid_record(short_code, db)
    email_norm = visitor_email.strip().lower()
    response = _log_click_and_redirect(record, request, db, visitor_email=email_norm)
    if record.expires_at:
        max_age = max(0, int((record.expires_at - datetime.utcnow()).total_seconds()))
    else:
        max_age = 60 * 60 * 24 * 365
    response.set_cookie(
        _visited_cookie_name(short_code),
        urllib.parse.quote(email_norm),
        max_age=max_age,
        httponly=True,
        samesite="lax",
    )
    return response


# ── Local Deploy ──────────────────────────────────────────────────────────────

LOCAL_HOSTS = {"localhost", "127.0.0.1", "aci1878"}
GIT_PATH = r"C:\Program Files\Git\cmd\git.exe"

@app.post("/admin/deploy", response_class=HTMLResponse)
def admin_deploy(request: Request, commit_msg: str = Form("Guncelleme"), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        return RedirectResponse(url="/", status_code=303)

    host = request.headers.get("host", "").split(":")[0]
    if host not in LOCAL_HOSTS:
        return HTMLResponse("<p>Bu işlem sadece yerel ortamda kullanılabilir.</p>", status_code=403)

    repo_dir = os.path.dirname(os.path.abspath(__file__))
    env = {**os.environ, "PATH": os.environ.get("PATH", "") + r";C:\Program Files\Git\cmd"}

    try:
        subprocess.run([GIT_PATH, "add", "."], cwd=repo_dir, check=True, capture_output=True)
        result = subprocess.run(
            [GIT_PATH, "commit", "-m", commit_msg],
            cwd=repo_dir, capture_output=True, text=True, env=env
        )
        if result.returncode not in (0, 1):
            raise subprocess.CalledProcessError(result.returncode, "commit", result.stderr)
        push = subprocess.run(
            [GIT_PATH, "push"],
            cwd=repo_dir, check=True, capture_output=True, text=True, env=env
        )
        output = push.stdout or push.stderr or "Push tamamlandı."
        status = "success"
    except subprocess.CalledProcessError as e:
        output = e.stderr if hasattr(e, "stderr") and e.stderr else str(e)
        status = "error"

    return HTMLResponse(f"""
    <html><head><meta charset="UTF-8">
    <style>body{{font-family:monospace;background:#0d1b3e;color:#f0f4ff;padding:2rem;}}
    .ok{{color:#2ecc71;}}.err{{color:#e74c3c;}}
    a{{color:#c9a84c;}}</style></head><body>
    <h3 class="{'ok' if status=='success' else 'err'}">
    {'✓ GitHub\'a gönderildi' if status=='success' else '✗ Hata oluştu'}
    </h3>
    <pre>{output}</pre>
    <a href="/">← Panele dön</a>
    </body></html>
    """)
