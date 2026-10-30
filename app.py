
from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from secrets import token_hex
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY", "truewallet-demo-secret-change-me"
)

DB_NAME = "truewallet.db"

# Lưu giao dịch demo trong bộ nhớ
transactions = []


# =========================
# DATABASE
# =========================
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


init_db()


# =========================
# KIỂM TRA ĐĂNG NHẬP
# =========================
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# =========================
# ĐĂNG KÝ
# =========================
@app.route("/register", methods=["GET", "POST"])
def register():
    if "username" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or len(username) < 3 or len(username) > 30:
            return render_template(
                "register.html",
                error="Tên đăng nhập phải có từ 3 đến 30 ký tự."
            )

        if not all(c.isalnum() or c in "_-" for c in username):
            return render_template(
                "register.html",
                error="Tên đăng nhập chỉ được gồm chữ, số, dấu gạch ngang và gạch dưới."
            )

        if len(password) < 8:
            return render_template(
                "register.html",
                error="Mật khẩu phải có ít nhất 8 ký tự."
            )

        if len(password) > 128:
            return render_template(
                "register.html",
                error="Mật khẩu không được vượt quá 128 ký tự."
            )

        if password != confirm_password:
            return render_template(
                "register.html",
                error="Mật khẩu xác nhận không khớp."
            )

        password_hash = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO users
                    (username, password_hash, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        password_hash,
                        datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                    )
                )

            return render_template(
                "login.html",
                message="Đăng ký thành công! Hãy đăng nhập."
            )

        except sqlite3.IntegrityError:
            return render_template(
                "register.html",
                error="Tên đăng nhập đã tồn tại. Hãy chọn tên khác."
            )

    return render_template("register.html")


# =========================
# ĐĂNG NHẬP
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["username"] = user["username"]
            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Tên đăng nhập hoặc mật khẩu không đúng."
        )

    return render_template("login.html")


# =========================
# ĐĂNG XUẤT
# =========================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================
# TRANG CHỦ
# =========================
@app.route("/")
@login_required
def home():
    user_transactions = [
        t for t in transactions
        if t["sender"] == session["username"]
    ]

    return render_template(
        "index.html",
        username=session["username"],
        transactions=user_transactions
    )


# =========================
# CHUYỂN TIỀN DEMO
# =========================
@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    if request.method == "POST":
        recipient = request.form.get("recipient", "").strip()
        account = request.form.get("account", "").strip()
        message = request.form.get("message", "").strip()

        try:
            amount = int(request.form.get("amount", "0"))
        except (ValueError, TypeError):
            amount = 0

        if not recipient or not account or amount < 1000:
            return render_template(
                "transfer.html",
                error="Vui lòng nhập đầy đủ thông tin và số tiền từ 1.000 VNĐ."
            )

        transaction = {
            "id": "TW-" + token_hex(4).upper(),
            "sender": session["username"],
            "recipient": recipient,
            "account": account,
            "amount": amount,
            "message": message or "Không có",
            "created_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "status": "Đã tạo giao dịch demo",
            "encryption_status": "Chưa thực hiện mã hóa"
        }

        transactions.insert(0, transaction)
        session["last_transaction_id"] = transaction["id"]

        return redirect(url_for("encryption"))

    return render_template("transfer.html")


# =========================
# MÃ HÓA AES + RSA
# =========================
@app.route("/encryption")
@login_required
def encryption():
    transaction_id = session.get("last_transaction_id")

    transaction = next(
        (
            t for t in transactions
            if t["id"] == transaction_id
            and t["sender"] == session["username"]
        ),
        None
    )

    return render_template(
        "encryption.html",
        transaction=transaction
    )


# =========================
# KẾT QUẢ VÀ LỊCH SỬ
# =========================
@app.route("/result")
@login_required
def result():
    user_transactions = [
        t for t in transactions
        if t["sender"] == session["username"]
    ]

    transaction_id = session.get("last_transaction_id")

    last_result = next(
        (
            t for t in user_transactions
            if t["id"] == transaction_id
        ),
        None
    )

    return render_template(
        "result.html",
        result=last_result,
        transactions=user_transactions
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
