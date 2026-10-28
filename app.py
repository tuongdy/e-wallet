
from datetime import datetime, timezone
from uuid import uuid4

from flask import Flask, request, jsonify, render_template
from crypto import encrypt_transaction, decrypt_transaction

app = Flask(__name__)


@app.route("/")
def home():
    return "E-Wallet Running"

@app.route("/transfer")
def transfer_page():
    return render_template("transfer.html")

@app.route("/result")
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
def transfer():
    # 1. Nhan du lieu JSON
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Du lieu JSON khong hop le"
        }), 400

    # 2. Lay thong tin giao dich
    sender = data.get("sender")
    receiver = data.get("receiver")
    amount = data.get("amount")
    currency = data.get("currency", "VND")
    content = data.get("content", "")

    # 3. Kiem tra nguoi gui
    if not isinstance(sender, str) or not sender.strip():
        return jsonify({
            "success": False,
            "message": "Nguoi gui khong hop le"
        }), 400

    # 4. Kiem tra nguoi nhan
    if not isinstance(receiver, str) or not receiver.strip():
        return jsonify({
            "success": False,
            "message": "Nguoi nhan khong hop le"
        }), 400

    sender = sender.strip()
    receiver = receiver.strip()

    if sender == receiver:
        return jsonify({
            "success": False,
            "message": "Khong the chuyen tien cho chinh minh"
        }), 400

    # 5. Kiem tra so tien
    if type(amount) is not int or amount <= 0:
        return jsonify({
            "success": False,
            "message": "So tien phai la so nguyen duong"
        }), 400

    # 6. Kiem tra don vi tien te
    if currency != "VND":
        return jsonify({
            "success": False,
            "message": "Chi ho tro don vi VND"
        }), 400

    # 7. Kiem tra noi dung
    if not isinstance(content, str) or len(content) > 255:
        return jsonify({
            "success": False,
            "message": "Noi dung giao dich khong hop le"
        }), 400

    # 8. Tao thong tin giao dich
    transaction = {
        "transaction_id": "GD-" + uuid4().hex[:12].upper(),
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "currency": currency,
        "content": content,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Ma hoa giao dich bang AES + RSA
    encrypted_transaction = encrypt_transaction(transaction)

    # 9. Tra ve ket qua giao dich da ma hoa (demo)
    return jsonify({
        "success": True,
        "status": "encrypted_demo",
        "message": "Giao dich hop le va da duoc ma hoa AES + RSA",
        "transaction_id": transaction["transaction_id"],
        "transaction": transaction,
        "encrypted_transaction": encrypted_transaction
    }), 200


@app.route("/api/decrypt", methods=["POST"])
def decrypt_api():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "verified": False,
            "message": "Du lieu JSON khong hop le"
        }), 400

    encrypted_package = data.get("encrypted_transaction")

    if not isinstance(encrypted_package, dict):
        return jsonify({
            "success": False,
            "verified": False,
            "message": "Thieu goi du lieu ma hoa"
        }), 400

    try:
        decrypted_transaction = decrypt_transaction(encrypted_package)

        return jsonify({
            "success": True,
            "verified": True,
            "message": "Giai ma va xac thuc AES-GCM thanh cong",
            "decrypted_transaction": decrypted_transaction
        }), 200

    except (ValueError, KeyError, TypeError) as error:
        return jsonify({
            "success": False,
            "verified": False,
            "message": "Giai ma hoac xac thuc that bai"
        }), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
