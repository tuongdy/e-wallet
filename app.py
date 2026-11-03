
import json
import os
import sqlite3
import base64
import hashlib
import re
from functools import wraps
from datetime import datetime, timezone
from uuid import uuid4

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session
)
from werkzeug.security import generate_password_hash, check_password_hash

from crypto import encrypt_transaction, decrypt_transaction, test_wrong_private_key
from security_tests import run_all_tests

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY chưa được cấu hình hoặc không đủ độ dài."
    )

app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
DB_NAME = "truewallet.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    # Tạo bảng users
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            balance INTEGER NOT NULL DEFAULT 10000000
        )
    """)

    # Kiểm tra cột balance
    columns = [
        row[1] for row in conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "balance" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN balance INTEGER NOT NULL DEFAULT 10000000
        """)

        # Tạo bảng transactions
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT NOT NULL UNIQUE,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            amount INTEGER NOT NULL,
            currency TEXT NOT NULL,
            content TEXT,
            timestamp TEXT NOT NULL,
            encrypted_package TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        )
    """)

    # Bổ sung cột chống xử lý giao dịch trùng
    columns = [
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(transactions)"
        ).fetchall()
    ]

    if "idempotency_key" not in columns:
        conn.execute(
            "ALTER TABLE transactions ADD COLUMN idempotency_key TEXT"
        )

    if "request_hash" not in columns:
        conn.execute(
            "ALTER TABLE transactions ADD COLUMN request_hash TEXT"
        )
       # Phân biệt giao dịch cũ đã cộng tiền và giao dịch mới đang chờ xác nhận
    columns = [
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(transactions)"
        ).fetchall()
    ]

    if "settlement_status" not in columns:
        conn.execute("""
            ALTER TABLE transactions
            ADD COLUMN settlement_status TEXT NOT NULL DEFAULT 'completed'
        """)
    # Tạo bảng processed_transactions
    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed_transactions (
            transaction_id TEXT PRIMARY KEY,
            processed_at TEXT NOT NULL
        )
    """)

           # Tạo bảng security_events để lưu nhật ký bảo mật
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            scenario TEXT,
            method TEXT,
            endpoint TEXT,
            http_status INTEGER,
            result TEXT,
            source_ip TEXT,
            username TEXT,
            timestamp TEXT NOT NULL,
            message TEXT
        )
    """)
    conn.commit()
    conn.close()
def log_security_event(
    event_type,
    scenario,
    result,
    message,
    http_status=None
):
    conn = get_db()

    try:
        conn.execute("""
            INSERT INTO security_events (
                event_type,
                scenario,
                method,
                endpoint,
                http_status,
                result,
                source_ip,
                username,
                timestamp,
                message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_type,
            scenario,
            request.method,
            request.path,
            http_status,
            result,
            request.remote_addr,
            session.get("username"),
            datetime.now(timezone.utc).isoformat(),
            message
        ))

        conn.commit()

    except sqlite3.Error as e:
        print("Security logging error:", str(e))

    finally:
        conn.close()
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


init_db()
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not 3 <= len(username) <= 30:
            return render_template(
                "register.html",
                error="Tên đăng nhập phải có từ 3 đến 30 ký tự."
            )

        if not all(c.isalnum() or c in "_-" for c in username):
            return render_template(
                "register.html",
                error="Tên đăng nhập chỉ được chứa chữ, số, dấu gạch dưới và gạch ngang."
            )

        if not 8 <= len(password) <= 128:
            return render_template(
                "register.html",
                error="Mật khẩu phải có từ 8 đến 128 ký tự."
            )

        if password != confirm_password:
            return render_template(
                "register.html",
                error="Mật khẩu xác nhận không khớp."
            )

        conn = get_db()

        try:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(password),
                    datetime.now(timezone.utc).isoformat()
                )
            )

            conn.commit()
            conn.close()

            return render_template(
                "login.html",
                message="Đăng ký thành công! Hãy đăng nhập."
            )

        except sqlite3.IntegrityError:
            conn.close()

            return render_template(
                "register.html",
                error="Tên đăng nhập đã tồn tại."
            )

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["username"] = user["username"]
            session.permanent = False
            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Tên đăng nhập hoặc mật khẩu không chính xác."
        )

    return render_template("login.html")


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@login_required
def home():
    conn = get_db()

    user = conn.execute(
        "SELECT balance FROM users WHERE username = ?",
        (session["username"],)
    ).fetchone()

    conn.close()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        username=session["username"],
        balance=user["balance"],
        transactions=[]
    )
@app.route("/transfer")
@login_required
def transfer():
    return render_template(
        "transfer.html",
        username=session["username"]
    )
@app.route("/encryption")
@login_required
def encryption_page():
    return render_template("encryption.html")

@app.route("/security")
@login_required
def security_page():
    return render_template("security.html")

@app.route("/hacker-simulation")
@login_required
def hacker_simulation():
    return render_template("hacker_simulation.html")

@app.route("/result")
@login_required
def result_page():
    return render_template("result.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "status": "ok",
        "service": "e-wallet-backend",
        "encryption_integrated": True
    }), 200


@app.route("/api/transfer", methods=["POST"])
@login_required
def transfer_api():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Dữ liệu JSON không hợp lệ"
        }), 400

    sender = session["username"]
    receiver = data.get("receiver")
    amount = data.get("amount")
    password = data.get("password")
    currency = data.get("currency", "VND")
    content = data.get("content", "")
    idempotency_key = data.get("idempotency_key")

    # 1. Kiểm tra người nhận
    if not isinstance(receiver, str) or not receiver.strip():
        return jsonify({
            "success": False,
            "message": "Người nhận không hợp lệ"
        }), 400

    receiver = receiver.strip()

    if receiver.lower() == sender.lower():
        return jsonify({
            "success": False,
            "message": "Không thể chuyển tiền cho chính mình"
        }), 400

    # 2. Kiểm tra số tiền
    if type(amount) is not int or amount <= 0 or amount > 1000000000:
        return jsonify({
            "success": False,
            "message": "Số tiền không hợp lệ"
        }), 400

    if currency != "VND":
        return jsonify({
            "success": False,
            "message": "Chỉ hỗ trợ VND"
        }), 400

    if not isinstance(content, str) or len(content) > 200:
        return jsonify({
            "success": False,
            "message": "Nội dung giao dịch không hợp lệ"
        }), 400

    # 3. Kiểm tra mã nhận diện yêu cầu
    if (
        not isinstance(idempotency_key, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", idempotency_key)
    ):
        return jsonify({
            "success": False,
            "message": "Mã nhận diện yêu cầu không hợp lệ"
        }), 400

    conn = get_db()

    try:
        # Bắt đầu transaction để tránh xử lý đồng thời
        conn.execute("BEGIN IMMEDIATE")

        # 4. Kiểm tra người gửi
        sender_account = conn.execute(
            """
            SELECT username, password_hash, balance
            FROM users
            WHERE username = ?
            """,
            (sender,)
        ).fetchone()

        if not sender_account:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Không tìm thấy tài khoản người gửi"
            }), 404

        # 5. Xác thực lại mật khẩu
        if not isinstance(password, str) or not password:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Vui lòng nhập mật khẩu xác nhận."
            }), 400

        if not check_password_hash(
            sender_account["password_hash"],
            password
        ):
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Mật khẩu xác nhận không chính xác."
            }), 401

        # 6. Kiểm tra người nhận
        recipient = conn.execute(
            "SELECT username FROM users WHERE username = ?",
            (receiver,)
        ).fetchone()

        if not recipient:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Tài khoản người nhận không tồn tại"
            }), 404

        receiver = recipient["username"]

        # 7. Tạo mã băm đại diện cho nội dung yêu cầu
        request_data = {
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "currency": currency,
            "content": content
        }

        request_hash = hashlib.sha256(
            json.dumps(
                request_data,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

        # 8. Kiểm tra yêu cầu đã được xử lý trước đó chưa
        existing = conn.execute(
            """
            SELECT transaction_id, sender, receiver,
                   amount, currency, content, timestamp,
                   encrypted_package, status, request_hash
            FROM transactions
            WHERE sender = ? AND idempotency_key = ?
            """,
            (sender, idempotency_key)
        ).fetchone()

        if existing:
            # Cùng mã yêu cầu nhưng nội dung khác
            if existing["request_hash"] != request_hash:
                conn.rollback()
                return jsonify({
                    "success": False,
                    "message": "Mã yêu cầu đã được sử dụng cho giao dịch khác."
                }), 409

            # Cùng yêu cầu: trả lại kết quả cũ, không chuyển tiền lần nữa
            encrypted_package = json.loads(
                existing["encrypted_package"]
            )

            current_balance = conn.execute(
                "SELECT balance FROM users WHERE username = ?",
                (sender,)
            ).fetchone()["balance"]

            conn.commit()

            return jsonify({
                "success": True,
                "already_processed": True,
                "status": existing["status"],
                "message": "Giao dịch đã được xử lý trước đó.",
                "transaction_id": existing["transaction_id"],
                "transaction": {
                    "transaction_id": existing["transaction_id"],
                    "sender": existing["sender"],
                    "receiver": existing["receiver"],
                    "amount": existing["amount"],
                    "currency": existing["currency"],
                    "content": existing["content"],
                    "timestamp": existing["timestamp"],
                    "status": existing["status"]
                },
                "encrypted_transaction": encrypted_package,
                "balance": current_balance
            }), 200

        # 9. Kiểm tra số dư
        if sender_account["balance"] < amount:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Số dư không đủ để thực hiện giao dịch"
            }), 400

        # 10. Tạo thông tin giao dịch
        transaction = {
            "transaction_id": "GD-" + uuid4().hex[:12].upper(),
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "currency": currency,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # 11. Mã hóa giao dịch bằng AES + RSA
        encrypted_transaction = encrypt_transaction(transaction)

               # 12. Chưa cập nhật số dư tại thời điểm gửi yêu cầu.
        # Số dư chỉ được cập nhật khi người nhận xác nhận.

        # 13. Lưu giao dịch và mã chống gửi trùng
        conn.execute("""
            INSERT INTO transactions (
                transaction_id,
                sender,
                receiver,
                amount,
                currency,
                content,
                timestamp,
                encrypted_package,
                status,
                idempotency_key,
                request_hash,
                settlement_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            transaction["transaction_id"],
            sender,
            receiver,
            amount,
            currency,
            content,
            transaction["timestamp"],
            json.dumps(encrypted_transaction),
            "pending",
            idempotency_key,
            request_hash,
            "pending"
        ))

        # 15. Lấy số dư mới
        new_balance = conn.execute(
            "SELECT balance FROM users WHERE username = ?",
            (sender,)
        ).fetchone()["balance"]

        conn.commit()

        return jsonify({
            "success": True,
            "already_processed": False,
            "status": "pending",
            "message": "Giao dịch đã được mã hóa và chuyển tiền thành công",
            "transaction_id": transaction["transaction_id"],
            "transaction": transaction,
            "encrypted_transaction": encrypted_transaction,
            "balance": new_balance
        }), 200

    except Exception as e:
        conn.rollback()
        print("Lỗi chuyển tiền:", str(e))

        return jsonify({
            "success": False,
            "message": "Không thể xử lý giao dịch"
        }), 500

    finally:
        conn.close()

@app.route("/inbox")
@login_required
def inbox():
    return render_template("inbox.html")


@app.route("/api/inbox", methods=["GET"])
def inbox_api():
    if "username" not in session:
        return jsonify({
            "success": False,
            "message": "Vui lòng đăng nhập"
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT transaction_id, sender, receiver,
               amount, currency, content, timestamp, status
        FROM transactions
        WHERE receiver = ?
        ORDER BY id DESC
    """, (session["username"],)).fetchall()

    conn.close()

    transactions = [dict(row) for row in rows]

    return jsonify({
        "success": True,
        "transactions": transactions
    }), 200
@app.route("/api/my-transactions", methods=["GET"])
@login_required
def my_transactions_api():
    username = session["username"]

    conn = get_db()

    rows = conn.execute("""
        SELECT transaction_id, sender, receiver,
               amount, currency, content, timestamp, status
        FROM transactions
        WHERE sender = ? OR receiver = ?
        ORDER BY id DESC
    """, (username, username)).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "transactions": [dict(row) for row in rows]
    }), 200


@app.route("/api/transactions/<transaction_id>/confirm", methods=["POST"])
@login_required
def confirm_transaction_api(transaction_id):
    conn = get_db()

    try:
        # Bắt đầu transaction để đảm bảo cập nhật số dư đồng bộ
        conn.execute("BEGIN IMMEDIATE")

        # 1. Lấy thông tin giao dịch
        transaction = conn.execute("""
            SELECT transaction_id, sender, receiver,
                   amount, status, settlement_status
            FROM transactions
            WHERE transaction_id = ?
              AND receiver = ?
        """, (
            transaction_id,
            session["username"]
        )).fetchone()

        if not transaction:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Không tìm thấy giao dịch."
            }), 404

        # 2. Kiểm tra trạng thái
        if transaction["status"] == "received":
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Giao dịch đã được xác nhận trước đó."
            }), 409

        if transaction["status"] != "pending":
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Trạng thái giao dịch không hợp lệ."
            }), 400

        # 3. Chỉ cập nhật số dư nếu giao dịch đang chờ thanh toán
        if transaction["settlement_status"] == "pending":
            amount = transaction["amount"]
            sender = transaction["sender"]
            receiver = transaction["receiver"]

            # Trừ tiền người gửi, đồng thời kiểm tra số dư
            cursor = conn.execute("""
                UPDATE users
                SET balance = balance - ?
                WHERE username = ?
                  AND balance >= ?
            """, (amount, sender, amount))

            if cursor.rowcount != 1:
                conn.rollback()
                return jsonify({
                    "success": False,
                    "message": "Số dư người gửi không đủ để hoàn tất giao dịch."
                }), 400

            # Cộng tiền cho người nhận
            cursor = conn.execute("""
                UPDATE users
                SET balance = balance + ?
                WHERE username = ?
            """, (amount, receiver))

            if cursor.rowcount != 1:
                conn.rollback()
                return jsonify({
                    "success": False,
                    "message": "Không thể cập nhật số dư người nhận."
                }), 400

        # 4. Cập nhật trạng thái giao dịch
        cursor = conn.execute("""
            UPDATE transactions
            SET status = 'received',
                settlement_status = 'completed'
            WHERE transaction_id = ?
              AND receiver = ?
              AND status = 'pending'
        """, (
            transaction_id,
            session["username"]
        ))

        if cursor.rowcount != 1:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "Không thể xác nhận giao dịch."
            }), 409

        # 5. Lấy số dư mới của người nhận
        balance = conn.execute("""
            SELECT balance
            FROM users
            WHERE username = ?
        """, (session["username"],)).fetchone()["balance"]

        conn.commit()

        return jsonify({
            "success": True,
            "status": "received",
            "balance": balance,
            "message": "Xác nhận giao dịch thành công. Số dư đã được cập nhật."
        }), 200

    except Exception as e:
        conn.rollback()
        print("Lỗi xác nhận giao dịch:", str(e))

        return jsonify({
            "success": False,
            "message": "Không thể xác nhận giao dịch."
        }), 500

    finally:
        conn.close()

@app.route("/api/transactions/<transaction_id>/encryption", methods=["GET"])
@login_required
def get_transaction_encryption(transaction_id):
    conn = get_db()

    row = conn.execute("""
        SELECT transaction_id, sender, receiver,
               amount, currency, content, timestamp,
               encrypted_package, status
        FROM transactions
        WHERE transaction_id = ?
          AND (sender = ? OR receiver = ?)
    """, (
        transaction_id,
        session["username"],
        session["username"]
    )).fetchone()

    conn.close()

    if not row:
        return jsonify({
            "success": False,
            "message": "Không tìm thấy giao dịch."
        }), 404

    try:
        encrypted_package = json.loads(row["encrypted_package"])

        transaction = {
            "transaction_id": row["transaction_id"],
            "sender": row["sender"],
            "receiver": row["receiver"],
            "amount": row["amount"],
            "currency": row["currency"],
            "content": row["content"],
            "timestamp": row["timestamp"]
        }

        decrypted_transaction = decrypt_transaction(encrypted_package)

        return jsonify({
            "success": True,
            "transaction": transaction,
            "encrypted_transaction": encrypted_package,
            "decrypted_transaction": decrypted_transaction,
            "verified": transaction == decrypted_transaction,
            "status": row["status"]
        }), 200

    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return jsonify({
            "success": False,
            "message": "Không thể giải mã giao dịch."
        }), 400
@app.route("/api/decrypt", methods=["POST"])
@login_required
def decrypt_api():
    try:
        data = request.get_json()

        if not data or "encrypted_transaction" not in data:
            return jsonify({
                "success": False,
                "verified": False,
                "message": "Thieu goi du lieu ma hoa"
            }), 400

        encrypted_transaction = data["encrypted_transaction"]

        # Giai ma giao dich bang AES + RSA
        decrypted_transaction = decrypt_transaction(
            encrypted_transaction
        )

        if not decrypted_transaction:
            return jsonify({
                "success": False,
                "verified": False,
                "message": "Khong the giai ma giao dich"
            }), 400

        return jsonify({
            "success": True,
            "verified": True,
            "message": "Giai ma va xac thuc thanh cong",
            "decrypted_transaction": decrypted_transaction
        }), 200

    except Exception as e:
        print("Loi API decrypt:", str(e))

        return jsonify({
            "success": False,
            "verified": False,
            "message": "Giai ma hoac xac thuc that bai"
        }), 400
@app.route("/api/test-wrong-key", methods=["POST"])
@login_required
def test_wrong_key_api():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Du lieu JSON khong hop le"
        }), 400

    encrypted_package = data.get("encrypted_transaction")

    if not isinstance(encrypted_package, dict):
        return jsonify({
            "success": False,
            "message": "Thieu goi du lieu ma hoa"
        }), 400

    try:
        result = test_wrong_private_key(encrypted_package)
        return jsonify(result), 200

    except (ValueError, KeyError, TypeError):
        return jsonify({
            "success": False,
            "rejected": False,
            "message": "Goi du lieu kiem thu khong hop le"
        }), 400


@app.route("/api/test-replay", methods=["POST"])
@login_required
def test_replay_api():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Du lieu JSON khong hop le"
        }), 400

    encrypted_package = data.get("encrypted_transaction")

    if not isinstance(encrypted_package, dict):
        return jsonify({
            "success": False,
            "message": "Thieu goi du lieu ma hoa"
        }), 400

    try:
        # 1. Giai ma goi du lieu
        transaction = decrypt_transaction(encrypted_package)

        # 2. Lay ma giao dich
        transaction_id = transaction.get("transaction_id")

        if not isinstance(transaction_id, str) or not transaction_id.strip():
            return jsonify({
                "success": False,
                "replay_detected": False,
                "message": "Ma giao dich khong hop le"
            }), 400

        # 3. Luu ma giao dich vao SQLite
        conn = get_db()

        try:
            conn.execute("""
                INSERT INTO processed_transactions (
                    transaction_id, processed_at
                )
                VALUES (?, ?)
            """, (
                transaction_id,
                datetime.now(timezone.utc).isoformat()
            ))

            conn.commit()

            return jsonify({
                "success": True,
                "replay_detected": False,
                "message": "Giao dich hop le, lan dau duoc ghi nhan",
                "transaction_id": transaction_id
            }), 200

        except sqlite3.IntegrityError:
            conn.rollback()

            return jsonify({
                "success": False,
                "replay_detected": True,
                "message": "Replay Attack: Giao dich da duoc xu ly truoc do",
                "transaction_id": transaction_id
            }), 409

        finally:
            conn.close()

    except (ValueError, KeyError, TypeError):
        return jsonify({
            "success": False,
            "replay_detected": False,
            "message": "Goi du lieu ma hoa khong hop le"
        }), 400

@app.route("/api/security-tests", methods=["POST"])
@login_required
def security_tests_api():
    try:
        result = run_all_tests()

        return jsonify({
            "success": True,
            "data": result
        }), 200

    except Exception as e:
        print("Lỗi kiểm thử bảo mật:", str(e))

        return jsonify({
            "success": False,
            "message": "Không thể chạy kiểm thử bảo mật"
        }), 500

# ==========================================
# ATTACK SIMULATION LAB - TEST DATA
# ==========================================

@app.route("/api/simulation/package", methods=["POST"])
@login_required
def simulation_package_api():
    """Tạo giao dịch giả lập và mã hóa bằng AES + RSA."""

    transaction = {
        "transaction_id": "SIM-" + uuid4().hex.upper(),
        "sender": session["username"],
        "receiver": "demo_receiver",
        "amount": 125000,
        "currency": "VND",
        "content": "Giao dich kiem thu bao mat",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        encrypted_package = encrypt_transaction(transaction)

        return jsonify({
            "success": True,
            "transaction": transaction,
            "encrypted_transaction": encrypted_package,
            "message": "Da tao goi giao dich gia lap."
        }), 200

    except Exception as e:
        print("Simulation package error:", str(e))

        return jsonify({
            "success": False,
            "message": "Khong the tao goi du lieu kiem thu."
        }), 500


# ==========================================
# DATA TAMPERING SIMULATION
# ==========================================

@app.route("/api/simulation/tampering", methods=["POST"])
@login_required
def simulation_tampering_api():
    """Thay đổi bản sao ciphertext để kiểm tra AES-GCM."""

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Du lieu JSON khong hop le."
        }), 400

    package = data.get("encrypted_transaction")

    if not isinstance(package, dict):
        return jsonify({
            "success": False,
            "message": "Thieu goi du lieu ma hoa."
        }), 400

    try:
        # Tạo bản sao để kiểm thử, không thay đổi gói gốc
        tampered_package = dict(package)

        ciphertext = base64.b64decode(
            tampered_package["encrypted_data"],
            validate=True
        )

        if not ciphertext:
            raise ValueError("Ciphertext rong.")

        # Thay đổi một byte trong ciphertext
        modified_ciphertext = bytes([
            ciphertext[0] ^ 1
        ]) + ciphertext[1:]

        tampered_package["encrypted_data"] = (
            base64.b64encode(modified_ciphertext)
            .decode("utf-8")
        )

        # Kiểm tra khả năng phát hiện dữ liệu bị thay đổi
        try:
            decrypt_transaction(tampered_package)

            log_security_event(
                event_type="DATA_TAMPERING",
                scenario="tampering",
                result="NOT_BLOCKED",
                message="Du lieu thay doi nhung chua bi tu choi.",
                http_status=200
            )

            return jsonify({
                "success": True,
                "rejected": False,
                "message": "Canh bao: du lieu thay doi nhung chua bi tu choi."
            }), 200

        except (ValueError, KeyError, TypeError):
            log_security_event(
                event_type="DATA_TAMPERING",
                scenario="tampering",
                result="BLOCKED",
                message="AES-GCM phat hien du lieu bi thay doi va tu choi giai ma.",
                http_status=200
            )

            return jsonify({
                "success": True,
                "rejected": True,
                "message": "AES-GCM phat hien du lieu bi thay doi va tu choi giai ma."
            }), 200

    except Exception as e:
        print("Tampering simulation error:", str(e))

        return jsonify({
            "success": False,
            "rejected": False,
            "message": "Khong the thuc hien kiem thu."
        }), 400

# ==========================================
# HYBRID ENCRYPTION SIMULATION
# ==========================================

@app.route("/api/simulation/hybrid", methods=["POST"])
@login_required
def simulation_hybrid_api():
    """Kiểm tra toàn bộ quy trình AES + RSA."""

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Du lieu JSON khong hop le."
        }), 400

    transaction = data.get("transaction")
    package = data.get("encrypted_transaction")

    if not isinstance(transaction, dict) or not isinstance(package, dict):
        return jsonify({
            "success": False,
            "message": "Thieu du lieu giao dich hoac goi ma hoa."
        }), 400

    try:
        # RSA khôi phục khóa AES và AES-GCM giải mã dữ liệu
        decrypted_transaction = decrypt_transaction(package)

        # So sánh dữ liệu sau giải mã với dữ liệu ban đầu
        verified = decrypted_transaction == transaction

        if verified:
            log_security_event(
                event_type="HYBRID_ENCRYPTION",
                scenario="hybrid",
                result="SUCCESS",
                message="RSA khoi phuc khoa AES va AES-GCM xac thuc du lieu thanh cong.",
                http_status=200
            )
        else:
            log_security_event(
                event_type="HYBRID_ENCRYPTION",
                scenario="hybrid",
                result="MISMATCH",
                message="Du lieu sau giai ma khong khop voi ban goc.",
                http_status=200
            )

        return jsonify({
            "success": True,
            "verified": verified,
            "message": (
                "RSA khoi phuc khoa AES va AES-GCM giai ma, xac thuc du lieu thanh cong."
                if verified else
                "Du lieu sau giai ma khong khop voi ban goc."
            ),
            "decrypted_transaction": decrypted_transaction,
            "key_id": package.get("key_id"),
            "key_fingerprint": package.get("key_fingerprint")
        }), 200

    except (ValueError, KeyError, TypeError) as e:

        log_security_event(
            event_type="HYBRID_ENCRYPTION",
            scenario="hybrid",
            result="BLOCKED",
            message="Giai ma hoac xac thuc that bai.",
            http_status=400
        )

        print("Hybrid encryption error:", str(e))

        return jsonify({
            "success": False,
            "verified": False,
            "message": "Giai ma hoac xac thuc that bai."
        }), 400

# ==========================================
# REPLAY ATTACK SIMULATION
# ==========================================

@app.route("/api/simulation/replay", methods=["POST"])
@login_required
def simulation_replay_api():
    """
    Mô phỏng gửi lại cùng một gói giao dịch.
    Dữ liệu kiểm thử được xóa sau khi hoàn tất.
    """

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Du lieu JSON khong hop le."
        }), 400

    package = data.get("encrypted_transaction")

    if not isinstance(package, dict):
        return jsonify({
            "success": False,
            "message": "Thieu goi du lieu ma hoa."
        }), 400

    conn = None

    try:
        transaction = decrypt_transaction(package)
        transaction_id = transaction.get("transaction_id")

        # Chỉ chấp nhận mã giao dịch dành riêng cho mô phỏng
        if (
            not isinstance(transaction_id, str)
            or not transaction_id.startswith("SIM-")
        ):
            return jsonify({
                "success": False,
                "message": "Chi chap nhan giao dich gia lap."
            }), 400

        conn = get_db()
        conn.execute("BEGIN IMMEDIATE")

        # Lần gửi đầu tiên
        conn.execute("""
            INSERT INTO processed_transactions (
                transaction_id, processed_at
            )
            VALUES (?, ?)
        """, (
            transaction_id,
            datetime.now(timezone.utc).isoformat()
        ))

        first_request_accepted = True

        # Lần gửi thứ hai: dùng lại cùng mã giao dịch
        try:
            conn.execute("""
                INSERT INTO processed_transactions (
                    transaction_id, processed_at
                )
                VALUES (?, ?)
            """, (
                transaction_id,
                datetime.now(timezone.utc).isoformat()
            ))

            replay_rejected = False

        except sqlite3.IntegrityError:
            replay_rejected = True

        # Xóa dữ liệu kiểm thử để không ảnh hưởng hệ thống
        conn.execute("""
            DELETE FROM processed_transactions
            WHERE transaction_id = ?
        """, (transaction_id,))

        conn.commit()
        log_security_event(
            event_type="REPLAY_SIMULATION",
            scenario="replay",
            result="BLOCKED" if replay_rejected else "NOT_BLOCKED",
            message=(
                "SQLite da tu choi lan gui lai do trung Transaction ID."
                if replay_rejected else
                "Canh bao: lan gui lai chua bi tu choi."
            ),
            http_status=200
        )
        return jsonify({
            "success": True,
            "first_request_accepted": first_request_accepted,
            "replay_rejected": replay_rejected,
            "transaction_id": transaction_id,
            "message": (
                "Giao dich lan dau duoc chap nhan; "
                "SQLite tu choi lan gui lai do trung Transaction ID."
                if replay_rejected else
                "Canh bao: he thong chua phat hien giao dich gui lai."
            )
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()

        print("Replay simulation error:", str(e))

        return jsonify({
            "success": False,
            "message": "Khong the thuc hien kiem thu Replay."
        }), 400

    finally:
        if conn:
            conn.close()

# ==========================================
# LIVE SECURITY MONITORING API
# ==========================================

@app.route("/api/security/events", methods=["GET"])
@login_required
def security_events_api():
    """Lấy danh sách sự kiện bảo mật gần nhất."""

    try:
        limit = request.args.get("limit", 50, type=int)
        limit = max(1, min(limit or 50, 100))

        conn = get_db()

        rows = conn.execute("""
            SELECT
                id,
                event_type,
                scenario,
                method,
                endpoint,
                http_status,
                result,
                timestamp,
                message
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        conn.close()

        return jsonify({
            "success": True,
            "events": [dict(row) for row in rows]
        }), 200

    except sqlite3.Error as e:
        print("Security events error:", str(e))

        return jsonify({
            "success": False,
            "message": "Không thể lấy nhật ký bảo mật."
        }), 500


@app.route("/api/security/summary", methods=["GET"])
@login_required
def security_summary_api():
    """Thống kê tổng quan các sự kiện bảo mật."""

    conn = get_db()

    try:
        total = conn.execute("""
            SELECT COUNT(*) FROM security_events
        """).fetchone()[0]

        blocked = conn.execute("""
            SELECT COUNT(*)
            FROM security_events
            WHERE result = 'BLOCKED'
        """).fetchone()[0]

        success = conn.execute("""
            SELECT COUNT(*)
            FROM security_events
            WHERE result = 'SUCCESS'
        """).fetchone()[0]

        return jsonify({
            "success": True,
            "summary": {
                "total_events": total,
                "blocked_events": blocked,
                "successful_events": success
            }
        }), 200

    except sqlite3.Error as e:
        print("Security summary error:", str(e))

        return jsonify({
            "success": False,
            "message": "Không thể thống kê sự kiện."
        }), 500

    finally:
        conn.close()


@app.route("/api/security/status", methods=["GET"])
@login_required
def security_status_api():
    """Kiểm tra trạng thái thực tế của Flask và SQLite."""

    conn = None
    database_status = "offline"

    try:
        conn = get_db()
        conn.execute("SELECT 1").fetchone()
        database_status = "connected"

    except sqlite3.Error as e:
        print("Security status error:", str(e))

    finally:
        if conn:
            conn.close()

    return jsonify({
        "success": True,
        "server": (
            "online" if database_status == "connected"
            else "degraded"
        ),
        "database": database_status,
        "security_logging": "enabled",
        "encryption": "AES-GCM + RSA-OAEP",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5001,
        debug=False
    )