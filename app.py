
from datetime import datetime, timezone
from uuid import uuid4

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/")
def home():
    return "E-Wallet Running"


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "status": "ok",
        "service": "e-wallet-backend",
        "encryption_integrated": False
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

    # 9. Tra ve ket qua kiem tra (chua chuyen tien)
    return jsonify({
        "success": True,
        "status": "validated_demo",
        "message": "Thong tin giao dich hop le",
        "transaction": transaction
    }), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
