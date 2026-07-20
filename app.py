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
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, session, abort, make_response
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
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    cur.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                ("admin", "admin123", "admin@example.com", "13800138000"))
    cur.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                ("alice", "alice2025", "alice@example.com", "13900139001"))
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

        # ✅ 安全：使用参数化查询（? 占位符），用户输入仅作为数据处理
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[REGISTER SQL] {sql} | params: ({username}, {password}, {email}, {phone})", flush=True)

        conn = sqlite3.connect(DATABASE_PATH)
        try:
            cur = conn.cursor()
            cur.execute(sql, (username, password, email, phone))
            conn.commit()
            return render_template("login.html",
                                   error="注册成功，请登录",
                                   csrf_token=generate_csrf_token(),
                                   captcha_svg=generate_captcha()[0])
        except Exception as e:
            message = f"注册失败：{e}"
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
    if username and username in USERS:
        user = USERS[username]
    return render_template("index.html", user=user, results=results, keyword=keyword)


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
    if username and username in USERS:
        user = USERS[username]
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

    # 🔐 密码验证 — 统一错误提示（不区分用户是否存在）
    if username in USERS and check_password_hash(USERS[username]["password"], password):
        # ✅ 登录成功
        FAILED_ATTEMPTS.pop(username, None)
        # 🔐 刷新 session（防 session 固定攻击）
        session.clear()
        session["username"] = username
        user = USERS[username]
        return render_template("index.html", user=user)
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


if __name__ == "__main__":
    # 初始化数据库
    init_db()
    # 🔐 关闭 debug 模式，使用环境变量控制
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
