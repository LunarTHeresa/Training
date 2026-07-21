"""
用户管理系统 - 安全加固版
==========================
修复清单：
  [高危] Debug=True → 改为 debug=False
  [高危] Secret Key 硬编码 → 从环境变量读取，无环境变量则自动生成
  [高危] 无验证码 → 新增 SVG 数学验证码
  [中危] 用户名校验泄露 → 统一错误提示，不区分用户是否存在
  [中危] Session 固定攻击 → 登录成功后刷新 session
  [中危] CSRF Token 可复用 → 验证后立即刷新
  [低危] Session 永不过期 → 设置 30 分钟过期
  [低危] HTML注释泄露默认账号 → 已清除
"""
import os
import sqlite3
import secrets
import time
import random
import string
from datetime import datetime, timedelta, date

from flask import (
    Flask, render_template, request, redirect, session, abort, make_response, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# =============================================
# 应用初始化
# =============================================
app = Flask(__name__)

# 🔐 从环境变量读取 secret_key，没有则自动生成
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# 🔐 Session 30 分钟过期
app.permanent_session_lifetime = timedelta(minutes=30)

# 🔐 上传文件大小限制
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


@app.context_processor
def inject_avatar():
    """在所有模板中注入当前用户的头像 URL"""
    avatar_filename = session.get("avatar")
    avatar_url = None
    if avatar_filename:
        avatar_url = url_for("static", filename=f"uploads/{avatar_filename}")
    return dict(avatar_url=avatar_url)

# =============================================
# 数据库初始化（SQLite — 用于注册和搜索）
# =============================================
DATABASE_DIR = os.path.join(os.path.dirname(__file__), "data")
DATABASE_PATH = os.path.join(DATABASE_DIR, "users.db")


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs(DATABASE_DIR, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（INSERT OR IGNORE 防止重复）；密码使用哈希存储
    cur.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000"))
    cur.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("✅ 数据库初始化完成")

# =============================================
# 🔐 第 1 层防护：IP 级别速率限制
# =============================================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    storage_uri="memory://",
)

# =============================================
# 用户数据
# =============================================
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# =============================================
# 🔐 第 2 层防护：账户锁定
# =============================================
FAILED_ATTEMPTS: dict = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 5


def is_account_locked(username: str) -> bool:
    record = FAILED_ATTEMPTS.get(username)
    if not record:
        return False
    if record["locked_until"] and datetime.now() < record["locked_until"]:
        return True
    if record["locked_until"] and datetime.now() >= record["locked_until"]:
        del FAILED_ATTEMPTS[username]
    return False


def record_failed_attempt(username: str):
    now = datetime.now()
    if username not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[username] = {"count": 0, "locked_until": None}
    record = FAILED_ATTEMPTS[username]
    record["count"] += 1
    if record["count"] >= MAX_ATTEMPTS:
        record["locked_until"] = now + timedelta(minutes=LOCKOUT_MINUTES)
        record["count"] = 0

# =============================================
# 🔐 验证码（SVG 数学验证码，无需外部依赖）
# =============================================

def generate_captcha() -> tuple[str, str]:
    """生成数学验证码，返回 (svg_xml, answer)"""
    a = random.randint(10, 99)
    b = random.randint(1, 9)
    op = random.choice(["+", "-"])
    if op == "-":
        if a < b:
            a, b = b, a
        answer = str(a - b)
    else:
        answer = str(a + b)

    question = f"{a} {op} {b} = ?"
    svg = _generate_captcha_svg(question)
    return svg, answer


def _generate_captcha_svg(text: str) -> str:
    """生成带噪点/干扰线的 SVG 验证码图片"""
    width = 200
    height = 60
    font_size = 28

    lines_svg = ""
    for _ in range(3):
        x1 = random.randint(0, width // 2)
        y1 = random.randint(0, height)
        x2 = random.randint(width // 2, width)
        y2 = random.randint(0, height)
        lines_svg += (
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="#999" stroke-width="1.5" stroke-dasharray="4,3" />\n'
        )

    dots = ""
    for _ in range(40):
        cx = random.randint(0, width)
        cy = random.randint(0, height)
        r = random.randint(1, 3)
        dots += f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="#bbb" opacity="0.6" />\n'

    colors = ["#e74c3c", "#2ecc71", "#3498db", "#9b59b6", "#e67e22"]
    color = random.choice(colors)
    rotation = random.randint(-8, 8)

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">\n'
        f'<rect width="{width}" height="{height}" fill="#f8f9fa" rx="6" />\n'
        f'{lines_svg}'
        f'{dots}'
        f'<text x="{width//2}" y="{height//2 + 10}" '
        f'font-size="{font_size}" font-family="monospace" font-weight="bold" '
        f'fill="{color}" text-anchor="middle" '
        f'transform="rotate({rotation} {width//2} {height//2})">\n'
        f'{text}</text>\n'
        f'</svg>'
    )
    return svg


# =============================================
# 🔐 CSRF 与输入校验
# =============================================

def generate_csrf_token() -> str:
    token = secrets.token_hex(16)
    session["csrf_token"] = token
    return token


def validate_login_input() -> tuple[str, str, str | None]:
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return "", "", "非法请求参数"
    username = username.strip()
    if not username:
        return "", "", "请输入用户名"
    if len(username) > 50 or len(password) > 100:
        return "", "", "参数长度异常"
    return username, password, None


# =============================================
# 路由
# =============================================

@app.before_request
def validate_content_type():
    if request.method == "POST":
        ct = request.content_type or ""
        if "application/x-www-form-urlencoded" not in ct and "multipart/form-data" not in ct:
            abort(400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面 — 使用参数化查询，防 SQL 注入"""
    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # 🔐 输入校验
        if not isinstance(username, str) or not isinstance(password, str):
            message = "非法请求参数"
        elif not username.strip() or not password:
            message = "用户名和密码不能为空"
        elif len(username) > 50 or len(password) > 100:
            message = "参数长度异常"
        elif email and len(email) > 100:
            message = "邮箱长度异常"
        elif phone and len(phone) > 20:
            message = "手机号长度异常"
        else:
            username = username.strip()
            # ✅ 安全：使用参数化查询（? 占位符），用户输入仅作为数据处理
            sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
            # 🔐 密码哈希存储；日志不记录明文密码
            hashed = generate_password_hash(password)
            print(f"[REGISTER SQL] {sql} | params: ({username}, ***, {email}, {phone})", flush=True)

            conn = sqlite3.connect(DATABASE_PATH)
            try:
                cur = conn.cursor()
                cur.execute(sql, (username, hashed, email, phone))
                conn.commit()
                return render_template("login.html",
                                       error="注册成功，请登录",
                                       csrf_token=generate_csrf_token(),
                                       captcha_svg=generate_captcha()[0])
            except sqlite3.IntegrityError:
                # 用户名唯一约束冲突 — 不泄露数据库细节
                message = "用户名已被占用，请更换"
            except Exception as e:
                print(f"[REGISTER ERROR] {e}", flush=True)
                message = "注册失败，请稍后重试"
            finally:
                conn.close()

    return render_template("register.html", message=message)


@app.route("/search")
def search():
    """搜索用户 — 使用参数化查询，防 SQL 注入"""
    keyword = request.args.get("keyword", "")
    results = []

    if keyword:
        # ✅ 安全：使用参数化查询（? 占位符），LIKE 参数也通过 ? 传递
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f"%{keyword}%"
        print(f"[SEARCH SQL] {sql} | params: ('{like_param}', '{like_param}')", flush=True)

        conn = sqlite3.connect(DATABASE_PATH)
        try:
            cur = conn.cursor()
            cur.execute(sql, (like_param, like_param))
            rows = cur.fetchall()
            for row in rows:
                results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        except Exception as e:
            print(f"[SEARCH ERROR] {e}", flush=True)
        finally:
            conn.close()

    # 渲染首页并传递搜索结果
    username = session.get("username")
    user = None
    if username:
        if username in USERS:
            user = USERS[username]
        else:
            conn = sqlite3.connect(DATABASE_PATH)
            try:
                cur = conn.cursor()
                cur.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
                row = cur.fetchone()
                if row:
                    user = {
                        "username": row[0],
                        "email": row[1],
                        "phone": row[2],
                        "role": "user",
                        "balance": 0,
                    }
            except Exception:
                pass
            finally:
                conn.close()
    return render_template("index.html", user=user, results=results, keyword=keyword)


UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")

# ⚠️ 危险后缀黑名单（禁止上传）
DENY_EXT = [
    ".php", ".php5", ".php4", ".php3", ".php2", ".php1",
    ".phtml", ".pht",
    ".pHp", ".pHp5", ".pHp4", ".pHp3", ".pHp2", ".pHp1",
    ".Html", ".Htm", ".pHtml",
    ".jsp", ".jspa", ".jspx", ".jsw", ".jsv", ".jspf", ".jtml",
    ".jSp", ".jSpx", ".jSpa", ".jSw", ".jSv", ".jSpf", ".jHtml",
    ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx", ".cer",
    ".aSp", ".aSpx", ".aSa", ".aSax", ".aScx", ".aShx", ".aSmx", ".cEr",
    ".swf", ".sWf",
    ".htaccess", ".ini", ".user.ini",
    ".sh", ".bash", ".zsh", ".fish",
    ".py", ".pyc", ".pyo",
    ".pl", ".pm", ".rb", ".exe", ".msi", ".bat", ".cmd", ".vbs",
    ".js", ".jse", ".wsf", ".wsh",
    ".war", ".jar",
]

# ✅ 允许的 MIME 类型
ALLOW_MIME = ["image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp"]

# 🔥 文件的魔术字节校验表（文件头签名）
MAGIC_BYTES = {
    b"\xff\xd8\xff":     [".jpg", ".jpeg", ".jpe"],
    b"\x89PNG\r\n\x1a\n": [".png"],
    b"GIF87a":           [".gif"],
    b"GIF89a":           [".gif"],
    b"RIFF":             [".webp"],  # WEBP 以 RIFF 开头，第8字节起为 WEBP
    b"BM":               [".bmp"],
}

# 🔥 文件内容中的危险关键词（防图马 + 防 XSS）
DANGEROUS_KEYWORDS = [
    b"<?php", b"<?=", b"<?PHP",
    b"eval(", b"eval (", b"base64_decode(", b"base64_decode (",
    b"system(", b"system (", b"exec(", b"exec (",
    b"shell_exec(", b"passthru(", b"popen(",
    b"assert(", b"assert (",
    b"<script", b"javascript:", b"onload=", b"onerror=",
    b"<?xml", b"<svg", b"<foreignObject",
]


def check_magic_bytes(data: bytes, ext: str) -> bool:
    """检测文件头魔术字节是否匹配扩展名"""
    for magic, extensions in MAGIC_BYTES.items():
        if data.startswith(magic):
            # WEBP 特殊处理：需要验证第8字节起的 WEBP 标记
            if magic == b"RIFF":
                return len(data) >= 12 and data[8:12] == b"WEBP"
            return ext.lower() in extensions
    return False


def check_dangerous_content(data: bytes) -> bool:
    """扫描文件内容中是否包含危险关键词"""
    for kw in DANGEROUS_KEYWORDS:
        if kw in data:
            return True
    return False


def deldot(filename: str) -> str:
    """删除文件名末尾的点（类似 PHP 的 deldot）"""
    while filename.endswith("."):
        filename = filename[:-1]
    return filename


def sanitize_filename(filename: str) -> str | None:
    """
    校验并净化文件名。
    返回安全的新文件名，或 None 表示拒绝。
    """
    # 去除首尾空格
    filename = filename.strip()

    # 检查是否为空
    if not filename:
        return None

    # 🔥 防 00 截断：检测空字节（%00 或 \0）
    if "\x00" in filename or "%00" in filename:
        return None

    # 🔥 防路径穿越：拒绝包含路径分隔符
    if "/" in filename or "\\" in filename or ".." in filename:
        return None

    # 🔥 防 ::$DATA 流注入
    filename = filename.replace("::$DATA", "")
    filename = filename.replace(":$DATA", "")

    # 🔥 防隐藏文件 / 配置文件（.htaccess, .user.ini 等）
    if filename.startswith("."):
        return None

    # 删除文件名末尾的点（防 Windows 自动去点 + 黑名单绕过）
    filename = deldot(filename)

    # 再次检查去点后是否为空
    if not filename:
        return None

    # 取扩展名（小写）
    ext = ""
    dot_pos = filename.rfind(".")
    if dot_pos != -1:
        ext = filename[dot_pos:].lower()

    # 🔥 检查黑名单
    if ext in DENY_EXT:
        return None

    return filename


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """头像上传 — 多重安全校验"""
    if "username" not in session:
        return redirect("/login")

    message = None
    file_url = None
    filename = None

    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            message = "请选择要上传的文件"
        else:
            original_filename = file.filename

            # 🔐 第 1 层：校验文件名（黑名单 + 00截断 + 特殊字符）
            safe_name = sanitize_filename(original_filename)
            if not safe_name:
                message = "文件名不合法，请使用常见图片格式"
            else:
                mime = file.content_type or ""
                if mime not in ALLOW_MIME:
                    message = f"文件类型 {mime} 不允许上传，仅支持图片格式"
                else:
                    ext = ""
                    dot_pos = safe_name.rfind(".")
                    if dot_pos != -1:
                        ext = safe_name[dot_pos:]
                    file.seek(0)
                    file_content = file.read()
                    if not check_magic_bytes(file_content, ext):
                        message = "文件内容与扩展名不匹配，请上传真实图片"
                    else:
                        try:
                            import io
                            from PIL import Image as PilImage
                            img = PilImage.open(io.BytesIO(file_content))
                            img.verify()
                            img = PilImage.open(io.BytesIO(file_content))
                        except Exception:
                            # 不是有效图片 → 检查是否夹带危险代码
                            if check_dangerous_content(file_content):
                                message = "文件内容包含危险代码，已拒绝"
                            else:
                                message = "文件不是有效的图片格式"
                    if not message:
                        try:
                            if img.mode in ("RGBA", "P"):
                                img = img.convert("RGB")
                            max_size = 3000
                            if img.width > max_size or img.height > max_size:
                                img.thumbnail((max_size, max_size), PilImage.LANCZOS)
                            new_name = f"{date.today().strftime('%Y%m%d')}_{random.randint(1000,9999)}{ext}"
                            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                            save_path = os.path.join(UPLOAD_FOLDER, new_name)
                            save_ext = "JPEG" if ext.lower() in [".jpg", ".jpeg", ".jpe"] else "PNG"
                            img.save(save_path, format=save_ext, quality=85)
                            print(f"[UPLOAD] {original_filename} → {new_name} ({mime}, {len(file_content)}b)", flush=True)
                        except Exception as e:
                            message = f"图片处理失败：{e}"
                    if not message:
                        session["avatar"] = new_name
                        session.modified = True
                        file_url = url_for("static", filename=f"uploads/{new_name}")
                        filename = new_name
                        message = "上传成功"

    return render_template("upload.html", message=message, file_url=file_url, filename=filename)


@app.route("/admin")
def admin_panel():
    username = session.get("username")
    user = USERS.get(username)
    if not user or user["role"] != "admin":
        abort(403)
    return render_template("admin.html", user=user)


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username:
        if username in USERS:
            user = USERS[username]
        else:
            # 从 SQLite 查注册用户的信息
            conn = sqlite3.connect(DATABASE_PATH)
            try:
                cur = conn.cursor()
                cur.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
                row = cur.fetchone()
                if row:
                    user = {
                        "username": row[0],
                        "email": row[1],
                        "phone": row[2],
                        "role": "user",
                        "balance": 0,
                    }
            except Exception:
                pass
            finally:
                conn.close()
    return render_template("index.html", user=user, results=[], keyword="")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def login():
    error = None
    user = None

    # 生成验证码（GET 请求时使用，POST 请求会重新生成）
    if request.method == "GET":
        captcha_svg, captcha_answer = generate_captcha()
        session["captcha_answer"] = captcha_answer
        return render_template(
            "login.html", error=None,
            csrf_token=generate_csrf_token(),
            captcha_svg=captcha_svg,
        )

    # ====== POST 处理 ======
    if "csrf_token" not in session:
        captcha_svg, captcha_answer = generate_captcha()
        session["captcha_answer"] = captcha_answer
        return render_template(
            "login.html", error="会话已过期，请重新登录",
            csrf_token=generate_csrf_token(),
            captcha_svg=captcha_svg,
        )

    # 🔐 输入校验
    username, password, input_err = validate_login_input()
    if input_err:
        captcha_svg, captcha_answer = generate_captcha()
        session["captcha_answer"] = captcha_answer
        return render_template(
            "login.html", error=input_err,
            csrf_token=generate_csrf_token(),
            captcha_svg=captcha_svg,
        )

    # 🔐 CSRF 验证（验证后立刻刷新 token）
    csrf_token_input = request.form.get("csrf_token", "")
    stored_token = session.pop("csrf_token", None)
    if not stored_token or csrf_token_input != stored_token:
        captcha_svg, captcha_answer = generate_captcha()
        session["captcha_answer"] = captcha_answer
        return render_template(
            "login.html", error="会话验证失败，请重新登录",
            csrf_token=generate_csrf_token(),
            captcha_svg=captcha_svg,
        )

    # 🔐 验证码校验
    captcha_input = request.form.get("captcha", "").strip()
    stored_answer = session.pop("captcha_answer", None)
    if not stored_answer or captcha_input != stored_answer:
        captcha_svg, captcha_answer = generate_captcha()
        session["captcha_answer"] = captcha_answer
        return render_template(
            "login.html", error="验证码错误",
            csrf_token=generate_csrf_token(),
            captcha_svg=captcha_svg,
        )

    # 🔐 检查账号是否被锁定
    if is_account_locked(username):
        remaining_seconds = int(
            (FAILED_ATTEMPTS[username]["locked_until"] - datetime.now()).total_seconds()
        )
        captcha_svg, captcha_answer = generate_captcha()
        session["captcha_answer"] = captcha_answer
        return render_template(
            "login.html", error=f"该账号已被锁定，请在 {remaining_seconds} 秒后重试",
            csrf_token=generate_csrf_token(),
            captcha_svg=captcha_svg,
        )

    # 🔐 密码验证 — 先查 USERS 字典，再查 SQLite 数据库
    login_ok = False
    user_data = None

    if username in USERS and check_password_hash(USERS[username]["password"], password):
        login_ok = True
        user_data = USERS[username]
    else:
        # 尝试从 SQLite 数据库查找（注册的用户）
        conn = sqlite3.connect(DATABASE_PATH)
        try:
            cur = conn.cursor()
            cur.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row and check_password_hash(row[1], password):
                login_ok = True
                user_data = {
                    "username": row[0],
                    "password": row[1],
                    "email": row[2],
                    "phone": row[3],
                    "role": "user",
                    "balance": 0,
                }
        except Exception:
            pass
        finally:
            conn.close()

    if login_ok:
        # ✅ 登录成功
        FAILED_ATTEMPTS.pop(username, None)
        # 🔐 刷新 session（防 session 固定攻击）
        session.clear()
        session["username"] = username
        return render_template("index.html", user=user_data)
    else:
        # ❌ 登录失败
        record_failed_attempt(username)
        # 🔐 渐进式延迟
        fail_count = FAILED_ATTEMPTS.get(username, {}).get("count", 0)
        delay = min(fail_count * 0.5, 3.0)
        if delay > 0:
            time.sleep(delay)
        captcha_svg, captcha_answer = generate_captcha()
        session["captcha_answer"] = captcha_answer
        return render_template(
            "login.html", error="用户名或密码错误",
            csrf_token=generate_csrf_token(),
            captcha_svg=captcha_svg,
        )


@app.route("/captcha")
def captcha():
    """返回验证码 SVG 图片（用于动态刷新）"""
    svg, answer = generate_captcha()
    session["captcha_answer"] = answer
    response = make_response(svg)
    response.headers["Content-Type"] = "image/svg+xml"
    return response


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# 模块加载时初始化数据库，确保 flask run / gunicorn 等任意启动方式下都可用
init_db()


if __name__ == "__main__":
    # 🔐 关闭 debug 模式，使用环境变量控制
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
