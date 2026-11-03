import json
import base64
import copy
import binascii
import sqlite3
import uuid
from datetime import datetime, timezone

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

from crypto import (
    encrypt_transaction,
    decrypt_transaction,
    test_wrong_private_key,
    create_aad,
    _PRIVATE_KEY
)


# ==========================================
# DU LIEU GIAO DICH KIEM THU
# ==========================================

def create_test_transaction():
    return {
        "transaction_id": "TEST-SECURITY-001",
        "sender": "user_test_01",
        "receiver": "user_test_02",
        "amount": 500000,
        "currency": "VND",
        "content": "Giao dich kiem thu bao mat",
        "timestamp": "2026-11-02T10:00:00+00:00"
    }


def make_result(test_id, name, success, message, category):
    return {
        "test_id": test_id,
        "name": name,
        "category": category,
        "success": bool(success),
        "status": "PASS" if success else "FAIL",
        "message": message
    }


# ==========================================
# AES-01: KIEM TRA GOI MA HOA
# ==========================================

def test_aes_encrypt():
    transaction = create_test_transaction()

    try:
        encrypted = encrypt_transaction(transaction)

        required = [
            "transaction_id",
            "encrypted_data",
            "encrypted_key",
            "nonce",
            "tag",
            "key_id",
            "key_fingerprint"
        ]

        if not all(
            field in encrypted and encrypted[field]
            for field in required
        ):
            raise ValueError("Thieu truong trong goi ma hoa")

        ciphertext = base64.b64decode(
            encrypted["encrypted_data"], validate=True
        )
        encrypted_key = base64.b64decode(
            encrypted["encrypted_key"], validate=True
        )
        nonce = base64.b64decode(
            encrypted["nonce"], validate=True
        )
        tag = base64.b64decode(
            encrypted["tag"], validate=True
        )

        valid = (
            len(ciphertext) > 0
            and len(encrypted_key) == 256
            and len(nonce) == 12
            and len(tag) == 16
            and len(encrypted["key_fingerprint"]) == 64
        )

        return make_result(
            "AES-01",
            "Kiểm tra cấu trúc gói mã hóa",
            valid,
            (
                "Gói mã hóa hợp lệ: nonce 12 byte, tag 16 byte, "
                "RSA ciphertext 256 byte."
                if valid else
                "Cấu trúc gói mã hóa không đáp ứng yêu cầu."
            ),
            "AES"
        )

    except Exception as error:
        return make_result(
            "AES-01",
            "Kiểm tra cấu trúc gói mã hóa",
            False,
            f"Lỗi kiểm tra: {type(error).__name__}",
            "AES"
        )


# ==========================================
# AES-02: KIEM TRA GIAI MA
# ==========================================

def test_aes_decrypt():
    transaction = create_test_transaction()

    try:
        encrypted = encrypt_transaction(transaction)
        decrypted = decrypt_transaction(encrypted)

        valid = decrypted == transaction

        return make_result(
            "AES-02",
            "Kiểm tra giải mã AES-GCM",
            valid,
            (
                "Dữ liệu sau giải mã trùng khớp hoàn toàn với dữ liệu ban đầu."
                if valid else
                "Dữ liệu sau giải mã không trùng khớp."
            ),
            "AES"
        )

    except Exception as error:
        return make_result(
            "AES-02",
            "Kiểm tra giải mã AES-GCM",
            False,
            f"Giải mã thất bại: {type(error).__name__}",
            "AES"
        )


# ==========================================
# INT-01: KIEM TRA CIPHERTEXT BI CHINH SUA
# ==========================================

def test_ciphertext_tampering():
    try:
        encrypted = encrypt_transaction(create_test_transaction())
        modified = copy.deepcopy(encrypted)

        ciphertext = bytearray(
            base64.b64decode(modified["encrypted_data"], validate=True)
        )

        if not ciphertext:
            raise ValueError("Ciphertext rong")

        ciphertext[0] ^= 1

        modified["encrypted_data"] = base64.b64encode(
            ciphertext
        ).decode("utf-8")

        rejected = False

        try:
            decrypt_transaction(modified)
        except (ValueError, KeyError, TypeError):
            rejected = True

        return make_result(
            "INT-01",
            "Phát hiện ciphertext bị thay đổi",
            rejected,
            (
                "AES-GCM từ chối dữ liệu có nội dung bị thay đổi."
                if rejected else
                "Dữ liệu bị thay đổi chưa bị từ chối."
            ),
            "INTEGRITY"
        )

    except Exception as error:
        return make_result(
            "INT-01",
            "Phát hiện ciphertext bị thay đổi",
            False,
            f"Lỗi kiểm thử: {type(error).__name__}",
            "INTEGRITY"
        )


# ==========================================
# INT-02: KIEM TRA AUTHENTICATION TAG
# ==========================================

def test_authentication_tag():
    try:
        encrypted = encrypt_transaction(create_test_transaction())
        modified = copy.deepcopy(encrypted)

        tag = bytearray(
            base64.b64decode(modified["tag"], validate=True)
        )

        tag[0] ^= 1

        modified["tag"] = base64.b64encode(
            tag
        ).decode("utf-8")

        rejected = False

        try:
            decrypt_transaction(modified)
        except (ValueError, KeyError, TypeError):
            rejected = True

        return make_result(
            "INT-02",
            "Xác thực Authentication Tag",
            rejected,
            (
                "AES-GCM từ chối Authentication Tag không hợp lệ."
                if rejected else
                "Authentication Tag không được xác thực đúng."
            ),
            "INTEGRITY"
        )

    except Exception as error:
        return make_result(
            "INT-02",
            "Xác thực Authentication Tag",
            False,
            f"Lỗi kiểm thử: {type(error).__name__}",
            "INTEGRITY"
        )


# ==========================================
# RSA-01: KIEM TRA PRIVATE KEY KHONG KHOP
# ==========================================

def test_rsa_wrong_key():
    try:
        encrypted = encrypt_transaction(create_test_transaction())
        result = test_wrong_private_key(encrypted)

        passed = (
            result.get("success") is True
            and result.get("rejected") is True
        )

        return make_result(
            "RSA-01",
            "Từ chối RSA Private Key không khớp",
            passed,
            (
                "RSA-OAEP từ chối khóa riêng không khớp."
                if passed else
                "Khóa riêng không khớp chưa được từ chối đúng."
            ),
            "RSA"
        )

    except Exception as error:
        return make_result(
            "RSA-01",
            "Từ chối RSA Private Key không khớp",
            False,
            f"Lỗi kiểm thử: {type(error).__name__}",
            "RSA"
        )


# ==========================================
# KEY-01: KIEM TRA TINH DUY NHAT KHOA PHIEN
# ==========================================

def test_session_key_uniqueness():
    transaction = create_test_transaction()

    try:
        encrypted_1 = encrypt_transaction(transaction)
        encrypted_2 = encrypt_transaction(transaction)

        fingerprint_1 = encrypted_1["key_fingerprint"]
        fingerprint_2 = encrypted_2["key_fingerprint"]

        passed = fingerprint_1 != fingerprint_2

        return make_result(
            "KEY-01",
            "Tính duy nhất của khóa phiên",
            passed,
            (
                "Hai lần mã hóa độc lập tạo ra hai khóa AES khác nhau."
                if passed else
                "Phát hiện fingerprint khóa phiên bị trùng."
            ),
            "KEY"
        )

    except Exception as error:
        return make_result(
            "KEY-01",
            "Tính duy nhất của khóa phiên",
            False,
            f"Lỗi kiểm thử: {type(error).__name__}",
            "KEY"
        )


# ==========================================
# KEY-02: KIEM TRA RSA KHOI PHUC KHOA AES
# ==========================================

def test_rsa_key_recovery():
    try:
        # 1. Tạo dữ liệu giao dịch ban đầu
        original = create_test_transaction()

        # 2. Mã hóa giao dịch bằng AES + RSA
        encrypted = encrypt_transaction(original)

        # 3. RSA giải mã khóa AES
        rsa_cipher = PKCS1_OAEP.new(
            _PRIVATE_KEY,
            hashAlgo=SHA256
        )

        encrypted_key = base64.b64decode(
            encrypted["encrypted_key"],
            validate=True
        )

        aes_key = rsa_cipher.decrypt(encrypted_key)

                # 4. Tạo lại AAD giống với lúc mã hóa
        aad = create_aad(
            encrypted["transaction_id"],
            encrypted["key_id"],
            encrypted["rsa_key_id"]
        )

        # 5. Giải mã dữ liệu bằng khóa AES vừa khôi phục
        ciphertext = base64.b64decode(
            encrypted["encrypted_data"],
            validate=True
        )

        nonce = base64.b64decode(
            encrypted["nonce"],
            validate=True
        )

        tag = base64.b64decode(
            encrypted["tag"],
            validate=True
        )

        aes_cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=nonce,
            mac_len=16
        )

        # AAD phải giống hoàn toàn với lúc mã hóa
        aes_cipher.update(aad)

        plaintext = aes_cipher.decrypt_and_verify(
            ciphertext,
            tag
        )

        # 6. Chuyển dữ liệu đã giải mã về dạng JSON
        recovered_transaction = json.loads(
            plaintext.decode("utf-8")
        )

        # 7. So sánh với dữ liệu ban đầu
        passed = (
            len(aes_key) == 32
            and recovered_transaction == original
        )

        return make_result(
            "KEY-02",
            "Khôi phục khóa phiên bằng RSA",
            passed,
            (
                "RSA khôi phục khóa AES 256-bit thành công; "
                "AES-GCM giải mã và xác thực dữ liệu chính xác."
                if passed else
                "Khóa AES hoặc dữ liệu giao dịch sau giải mã không khớp."
            ),
            "KEY"
        )

    except Exception as error:
        return make_result(
            "KEY-02",
            "Khôi phục khóa phiên bằng RSA",
            False,
            f"Lỗi kiểm thử: {type(error).__name__}",
            "KEY"
        )


# ==========================================
# REPLAY-01: KIEM TRA NGUYEN LY CHONG PHAT LAI
# ==========================================

def test_replay_detection():
    conn = None

    try:
        transaction = create_test_transaction()
        transaction_id = transaction["transaction_id"]

        conn = sqlite3.connect("truewallet.db")

        # Xoa ID kiem thu neu da ton tai tu lan chay truoc
        conn.execute(
            "DELETE FROM processed_transactions WHERE transaction_id = ?",
            (transaction_id,)
        )
        conn.commit()

        # Lan dau: ghi nhan giao dich
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

        first_accepted = conn.execute(
            "SELECT 1 FROM processed_transactions WHERE transaction_id = ?",
            (transaction_id,)
        ).fetchone() is not None

        # Lan hai: thu ghi lai cung ID
        second_rejected = False

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

        except sqlite3.IntegrityError:
            conn.rollback()
            second_rejected = True

        passed = first_accepted and second_rejected

        return make_result(
            "REPLAY-01",
            "Kiểm tra phát hiện giao dịch phát lại bằng SQLite",
            passed,
            (
                "SQLite ghi nhận giao dịch lần đầu và từ chối "
                "mã giao dịch trùng lặp ở lần thứ hai."
                if passed else
                "SQLite chưa từ chối được mã giao dịch trùng lặp."
            ),
            "REPLAY"
        )

    except Exception as error:
        return make_result(
            "REPLAY-01",
            "Kiểm tra phát hiện giao dịch phát lại bằng SQLite",
            False,
            f"Lỗi kiểm thử: {type(error).__name__}",
            "REPLAY"
        )

    finally:
        if conn:
            conn.close()

# ==========================================
# TONG HOP KET QUA
# ==========================================

def run_all_tests():
    tests = [
        test_aes_encrypt,
        test_aes_decrypt,
        test_ciphertext_tampering,
        test_authentication_tag,
        test_rsa_wrong_key,
        test_session_key_uniqueness,
        test_rsa_key_recovery,
        test_replay_detection
    ]

    results = [test() for test in tests]

    total = len(results)
    passed = sum(1 for item in results if item["success"])
    failed = total - passed

    return {
        "success": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "results": results
    }
