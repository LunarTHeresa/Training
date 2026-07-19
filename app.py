from flask import Flask, render_template, request, redirect, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
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
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
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


@app.route("/admin")
def admin_panel():
    username = session.get("username")
    user = USERS.get(username)
    # ⚠️ 这里应该有 role == "admin" 的校验，但故意没写
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
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # 🔐 第 2 层：检查账号是否被锁定
        if is_account_locked(username):
            remaining_seconds = int(
                (FAILED_ATTEMPTS[username]["locked_until"] - datetime.now()).total_seconds()
            )
            error = f"该账号已被锁定，请在 {remaining_seconds} 秒后重试"
            return render_template("login.html", error=error)

        if username in USERS and USERS[username]["password"] == password:
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

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
