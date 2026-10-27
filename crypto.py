
import json
import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# Tao cap khoa RSA cho server trong mo phong
_PRIVATE_KEY = RSA.generate(2048)
_PUBLIC_KEY = _PRIVATE_KEY.publickey()


def encrypt_transaction(data):
    """Ma hoa du lieu giao dich bang AES va khoa AES bang RSA."""

    if not isinstance(data, dict):
        raise TypeError("Du lieu giao dich phai la dictionary.")

    required = [
        "transaction_id",
        "sender",
        "receiver",
        "amount",
        "currency",
        "content",
        "timestamp"
    ]

    for field in required:
        if field not in data:
            raise ValueError(f"Thieu truong du lieu: {field}")

    # Tao khoa phien AES 256-bit
    aes_key = get_random_bytes(32)

    # Chuyen du lieu giao dich thanh JSON
    plaintext = json.dumps(
        data, ensure_ascii=False
    ).encode("utf-8")

    # Ma hoa du lieu bang AES-GCM
    nonce = get_random_bytes(12)
    aes_cipher = AES.new(
        aes_key, AES.MODE_GCM, nonce=nonce
    )
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

    # Dung khoa cong khai RSA ma hoa khoa AES
    rsa_cipher = PKCS1_OAEP.new(
        _PUBLIC_KEY, hashAlgo=SHA256
    )
    encrypted_key = rsa_cipher.encrypt(aes_key)

    # Tra ve du lieu da ma hoa
    return {
        "transaction_id": data["transaction_id"],
        "encrypted_data": base64.b64encode(
            ciphertext
        ).decode("utf-8"),
        "encrypted_key": base64.b64encode(
            encrypted_key
        ).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8")
    }


def decrypt_transaction(data):
    """Giai ma khoa AES bang RSA roi giai ma giao dich."""

    # Giai ma khoa AES bang khoa rieng RSA
    rsa_cipher = PKCS1_OAEP.new(
        _PRIVATE_KEY, hashAlgo=SHA256
    )

    encrypted_key = base64.b64decode(data["encrypted_key"])
    aes_key = rsa_cipher.decrypt(encrypted_key)

    # Giai ma du lieu bang AES-GCM
    ciphertext = base64.b64decode(data["encrypted_data"])
    nonce = base64.b64decode(data["nonce"])
    tag = base64.b64decode(data["tag"])

    aes_cipher = AES.new(
        aes_key, AES.MODE_GCM, nonce=nonce
    )

    plaintext = aes_cipher.decrypt_and_verify(
        ciphertext, tag
    )

    # Chuyen JSON ve dictionary
    return json.loads(plaintext.decode("utf-8"))
