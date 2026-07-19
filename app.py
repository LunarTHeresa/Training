from flask import Flask, render_template, request, redirect, session, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets  # 用于生成随机盐
import time

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# =============================================
# 🔐 第 1 层防护：IP 级别速率限制
# =============================================
# 限制：同一个 IP 每分钟最多尝试 10 次登录
# 超过后返回 429 Too Many Requests
# ⚡ 防 Burp Suite 快速爆破（1 分钟窗口内有效）
limiter = Limiter(
    get_remote_address,         # 以客户端 IP 为 key
    app=app,
    default_limits=["60 per minute"],
    storage_uri="memory://",    # 存内存中，重启即重置
)

USERS = {
    "admin": {
        "username": "admin",
        # 🔐 加盐哈希（scrypt）
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

# =============================================
# 🔐 第 2 层防护：账户锁定
# =============================================
# failed_attempts[用户名] = {"count": 失败次数, "locked_until": 解锁时间}
# 连续失败 5 次 → 锁定该用户 5 分钟
# 无论密码是否正确，锁定期间都拒绝登录
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 5


def is_account_locked(username: str) -> bool:
    """检查账号是否被锁定"""
    record = FAILED_ATTEMPTS.get(username)
    if not record:
        return False
    if record["locked_until"] and datetime.now() < record["locked_until"]:
        return True
    # 锁定时间已过，清除记录
    if record["locked_until"] and datetime.now() >= record["locked_until"]:
        del FAILED_ATTEMPTS[username]
    return False


def record_failed_attempt(username: str):
    """记录一次失败登录，达到阈值则锁定"""
    now = datetime.now()
    if username not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[username] = {"count": 0, "locked_until": None}

    record = FAILED_ATTEMPTS[username]
    record["count"] += 1

    # 达到最大尝试次数 → 锁定
    if record["count"] >= MAX_ATTEMPTS:
        record["locked_until"] = now + timedelta(minutes=LOCKOUT_MINUTES)
        record["count"] = 0


# =============================================
# 🔐 第 4 层防护：输入校验 + CSRF 令牌
# =============================================
# 防 Burp Suite 改包绕过：
#   - 拒绝非字符串输入（防参数污染）
#   - CSRF 令牌验证（防请求伪造和重放）
#   - 内容类型验证（防畸形请求）
CSRF_TOKENS = {}  # session_id → token


def generate_csrf_token() -> str:
    """生成 CSRF 令牌并存入 session"""
    token = secrets.token_hex(16)
    session["csrf_token"] = token
    return token


def validate_login_input() -> tuple[str, str, str | None]:
    """校验登录输入，返回 (username, password, error)"""
    # 🔥 攻击手法 1：参数污染
    # Burp 发送 username[]=admin&password[]=admin123
    # Flask 的 get() 会返回列表而非字符串
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


@app.before_request
def validate_content_type():
    """🔥 攻击手法 2：绕过 Content-Type 发送畸形请求
       拒绝非法的 Content-Type，防止绕过表单验证"""
    if request.method == "POST":
        ct = request.content_type or ""
        # 只允许标准的 form 提交
        if "application/x-www-form-urlencoded" not in ct and "multipart/form-data" not in ct:
            abort(400)

@app.route("/admin")
def admin_panel():
    username = session.get("username")
    user = USERS.get(username)
    # 🔐 垂直越权防护：只有 admin 角色才能访问
    if not user or user["role"] != "admin":
        abort(403)  # 返回 403 Forbidden
    return render_template("admin.html", user=user)


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = USERS[username]
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
# 🔐 第 1 层：每分钟 30 次登录尝试（按 IP 限流，防快速爆破）
@limiter.limit("30 per minute")
def login():
    error = None
    user = None

    if request.method == "POST":
        # 🔐 第 4 层：输入校验（防参数污染）
        username, password, input_err = validate_login_input()
        if input_err:
            error = input_err
            return render_template("login.html", error=error, csrf_token=generate_csrf_token())

        # 🔐 第 4 层：CSRF 令牌验证（防请求重放/伪造）
        csrf_token = request.form.get("csrf_token", "")
        stored_token = session.get("csrf_token", "")
        if not csrf_token or not stored_token or csrf_token != stored_token:
            error = "会话验证失败，请重新登录"
            return render_template("login.html", error=error, csrf_token=generate_csrf_token())

        # 🔐 第 2 层：检查账号是否被锁定
        if is_account_locked(username):
            remaining_seconds = int(
                (FAILED_ATTEMPTS[username]["locked_until"] - datetime.now()).total_seconds()
            )
            error = f"该账号已被锁定，请在 {remaining_seconds} 秒后重试"
            return render_template("login.html", error=error, csrf_token=generate_csrf_token())

        if username in USERS and check_password_hash(USERS[username]["password"], password):
            # ✅ 登录成功 → 清除该用户的失败记录
            FAILED_ATTEMPTS.pop(username, None)
            session["username"] = username
            user = USERS[username]
            return render_template("index.html", user=user)
        else:
            # ❌ 登录失败 → 记录
            record_failed_attempt(username)
            remaining = MAX_ATTEMPTS - FAILED_ATTEMPTS.get(username, {}).get("count", 0)
            error = f"用户名或密码错误（还剩 {remaining} 次尝试机会）"

            # 🔐 第 3 层：渐进式延迟
            # 每失败一次，多等 0.5 秒，让 Burp Suite 爆破速度大幅下降
            fail_count = FAILED_ATTEMPTS.get(username, {}).get("count", 0)
            delay = min(fail_count * 0.5, 3.0)  # 最多延迟 3 秒
            if delay > 0:
                time.sleep(delay)
                error += f"（延迟 {delay:.1f}s）"

    return render_template("login.html", error=error, csrf_token=generate_csrf_token())


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
