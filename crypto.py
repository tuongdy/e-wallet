
import json
import base64
import uuid
import os
import stat
import hmac

from pathlib import Path
from datetime import datetime, timezone

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# ==========================================
# 1. CAU HINH
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
KEY_DIR = BASE_DIR / "instance"
PRIVATE_KEY_FILE = KEY_DIR / "server_private.pem"

RSA_BITS = 2048
AES_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

FORMAT_VERSION = 2
ALGORITHM = "AES-256-GCM+RSA-2048-OAEP-SHA256"

MAX_PLAINTEXT_SIZE = 1024 * 1024
MAX_CIPHERTEXT_SIZE = 1024 * 1024


# ==========================================
# 2. QUAN LY KHOA RSA
# ==========================================

def validate_rsa_private_key(private_key):
    """Kiem tra khoa RSA Private Key."""

    if not private_key.has_private():
        raise RuntimeError("RSA Private Key khong hop le.")

    if private_key.size_in_bits() != RSA_BITS:
        raise RuntimeError("Khoa RSA phai co kich thuoc 2048 bit.")

    return private_key


def load_or_create_rsa_keys():
    """Doc khoa RSA cu hoac tao khoa moi neu chua ton tai."""

    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_FILE.is_symlink():
        raise RuntimeError("Khong chap nhan RSA key file la symbolic link.")

    try:
        os.chmod(KEY_DIR, 0o700)
    except OSError:
        if os.name == "posix":
            raise RuntimeError("Khong the bao ve thu muc RSA key.")

    if PRIVATE_KEY_FILE.exists():
        private_key = RSA.import_key(
            PRIVATE_KEY_FILE.read_bytes()
        )

        validate_rsa_private_key(private_key)

    else:
        private_key = RSA.generate(RSA_BITS)
        key_data = private_key.export_key()

        fd = None
        created = False

        try:
            fd = os.open(
                str(PRIVATE_KEY_FILE),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600
            )

            created = True

            with os.fdopen(fd, "wb") as key_file:
                fd = None
                key_file.write(key_data)
                key_file.flush()
                os.fsync(key_file.fileno())

        except FileExistsError:
            # Mot tien trinh khac vua tao khoa.
            private_key = RSA.import_key(
                PRIVATE_KEY_FILE.read_bytes()
            )

            validate_rsa_private_key(private_key)

        except Exception:
            if created:
                PRIVATE_KEY_FILE.unlink(missing_ok=True)
            raise

        finally:
            if fd is not None:
                os.close(fd)

    try:
        os.chmod(PRIVATE_KEY_FILE, 0o600)

        if os.name == "posix":
            mode = stat.S_IMODE(
                PRIVATE_KEY_FILE.stat().st_mode
            )

            if mode & 0o077:
                raise RuntimeError(
                    "RSA Private Key dang co quyen truy cap qua rong."
                )

    except OSError:
        if os.name == "posix":
            raise RuntimeError("Khong the bao ve RSA Private Key.")

    return private_key, private_key.publickey()


_PRIVATE_KEY, _PUBLIC_KEY = load_or_create_rsa_keys()


# Ma dinh danh on dinh cua RSA Public Key
_RSA_KEY_ID = SHA256.new(
    _PUBLIC_KEY.export_key(format="DER")
).hexdigest()[:16].upper()


# ==========================================
# 3. CAC HAM HO TRO
# ==========================================

def encode_base64(data):
    return base64.b64encode(data).decode("utf-8")


def decode_base64(value, field_name, max_size):
    """Giai ma Base64 va kiem tra dinh dang nghiem ngat."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"Truong {field_name} khong hop le.")

    try:
        decoded = base64.b64decode(
            value,
            validate=True
        )
    except Exception as exc:
        raise ValueError(
            f"Du lieu Base64 cua {field_name} khong hop le."
        ) from exc

    if len(decoded) > max_size:
        raise ValueError(
            f"Du lieu {field_name} vuot qua kich thuoc cho phep."
        )

    return decoded


def create_aad(transaction_id, key_id, rsa_key_id):
    """
    Tao Additional Authenticated Data.
    AAD khong bi ma hoa nhung duoc AES-GCM xac thuc.
    """

    metadata = {
        "version": FORMAT_VERSION,
        "algorithm": ALGORITHM,
        "transaction_id": transaction_id,
        "key_id": key_id,
        "rsa_key_id": rsa_key_id
    }

    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


# ==========================================
# 4. MA HOA GIAO DICH AES + RSA
# ==========================================

def encrypt_transaction(data):
    """Ma hoa giao dich bang AES-GCM va bao ve khoa AES bang RSA-OAEP."""

    if not isinstance(data, dict):
        raise TypeError("Du lieu giao dich phai la dictionary.")

    required_fields = [
        "transaction_id",
        "sender",
        "receiver",
        "amount",
        "currency",
        "content",
        "timestamp"
    ]

    for field in required_fields:
        if field not in data:
            raise ValueError(f"Thieu truong du lieu: {field}")

    transaction_id = data["transaction_id"]

    if not isinstance(transaction_id, str) or not transaction_id.strip():
        raise ValueError("Transaction ID khong hop le.")

    # Chuyen du lieu giao dich thanh JSON
    try:
        plaintext = json.dumps(
            data,
            ensure_ascii=False,
            allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Du lieu giao dich khong the chuyen thanh JSON.") from exc

    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise ValueError("Du lieu giao dich qua lon.")

    # Tao khoa phien AES-256 moi cho moi giao dich
    aes_key = get_random_bytes(AES_KEY_SIZE)

    # Ma nhan dien rieng cua khoa phien
    key_id = "KEY-" + uuid.uuid4().hex[:8].upper()

    key_created_at = datetime.now(
        timezone.utc
    ).isoformat()

    # Fingerprint la bam cua khoa AES, khong phai khoa AES
    key_fingerprint = SHA256.new(aes_key).hexdigest()

    # Tao AAD de bao ve metadata
    aad = create_aad(
        transaction_id,
        key_id,
        _RSA_KEY_ID
    )

    # Ma hoa du lieu bang AES-256-GCM
    nonce = get_random_bytes(NONCE_SIZE)

    aes_cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=TAG_SIZE
    )

    aes_cipher.update(aad)

    ciphertext, tag = aes_cipher.encrypt_and_digest(
        plaintext
    )

    # RSA Public Key bao ve khoa AES
    rsa_cipher = PKCS1_OAEP.new(
        _PUBLIC_KEY,
        hashAlgo=SHA256
    )

    encrypted_key = rsa_cipher.encrypt(aes_key)

    return {
        "version": FORMAT_VERSION,
        "algorithm": ALGORITHM,

        "transaction_id": transaction_id,

        "encrypted_data": encode_base64(ciphertext),
        "encrypted_key": encode_base64(encrypted_key),
        "nonce": encode_base64(nonce),
        "tag": encode_base64(tag),

        "key_id": key_id,
        "rsa_key_id": _RSA_KEY_ID,

        "key_created_at": key_created_at,
        "key_fingerprint": key_fingerprint
    }


# ==========================================
# 5. GIAI MA GIAO DICH
# ==========================================

def decrypt_transaction(data):
    """Khoi phuc khoa AES bang RSA va giai ma du lieu bang AES-GCM."""

    if not isinstance(data, dict):
        raise TypeError("Goi ma hoa khong hop le.")

    required_fields = [
        "transaction_id",
        "encrypted_data",
        "encrypted_key",
        "nonce",
        "tag"
    ]

    for field in required_fields:
        if field not in data:
            raise ValueError(f"Thieu truong ma hoa: {field}")

    transaction_id = data["transaction_id"]

    if not isinstance(transaction_id, str) or not transaction_id.strip():
        raise ValueError("Transaction ID khong hop le.")

    # Ho tro goi cu (version 1) va goi moi (version 2)
    version = data.get("version", 1)

    if version not in (1, FORMAT_VERSION):
        raise ValueError("Phien ban goi ma hoa khong duoc ho tro.")

    # Kiem tra metadata cua goi moi
    if version == FORMAT_VERSION:
        if data.get("algorithm") != ALGORITHM:
            raise ValueError("Thuat toan ma hoa khong khop.")

        if data.get("rsa_key_id") != _RSA_KEY_ID:
            raise ValueError("RSA Key ID khong khop voi khoa hien tai.")

        if not isinstance(data.get("key_id"), str):
            raise ValueError("Session Key ID khong hop le.")

        aad = create_aad(
            transaction_id,
            data["key_id"],
            data["rsa_key_id"]
        )

    else:
        # Goi cu khong co AAD
        aad = None

    # Kiem tra Base64
    encrypted_key = decode_base64(
        data["encrypted_key"],
        "encrypted_key",
        512
    )

    ciphertext = decode_base64(
        data["encrypted_data"],
        "encrypted_data",
        MAX_CIPHERTEXT_SIZE
    )

    nonce = decode_base64(
        data["nonce"],
        "nonce",
        NONCE_SIZE
    )

    tag = decode_base64(
        data["tag"],
        "tag",
        TAG_SIZE
    )

    # Kiem tra kich thuoc du lieu
    if len(encrypted_key) != RSA_BITS // 8:
        raise ValueError("Kich thuoc RSA Encrypted Key khong hop le.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce AES-GCM khong hop le.")

    if len(tag) != TAG_SIZE:
        raise ValueError("Authentication Tag khong hop le.")

    # Khoi phuc khoa AES bang RSA Private Key
    rsa_cipher = PKCS1_OAEP.new(
        _PRIVATE_KEY,
        hashAlgo=SHA256
    )

    try:
        aes_key = rsa_cipher.decrypt(encrypted_key)
    except ValueError as exc:
        raise ValueError(
            "Khong the khoi phuc khoa AES bang RSA Private Key."
        ) from exc

    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError("Khoa AES sau khi khoi phuc khong hop le.")

    # Doi chieu fingerprint neu duoc cung cap
    fingerprint = data.get("key_fingerprint")

    if fingerprint is not None:
        actual_fingerprint = SHA256.new(aes_key).hexdigest()

        if not isinstance(fingerprint, str) or not hmac.compare_digest(
            actual_fingerprint,
            fingerprint
        ):
            raise ValueError("Fingerprint cua khoa AES khong khop.")

    # Giai ma va xac thuc AES-GCM
    aes_cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=TAG_SIZE
    )

    if aad is not None:
        aes_cipher.update(aad)

    try:
        plaintext = aes_cipher.decrypt_and_verify(
            ciphertext,
            tag
        )
    except ValueError as exc:
        raise ValueError(
            "Du lieu khong hop le hoac xac thuc AES-GCM that bai."
        ) from exc

    # Kiem tra JSON
    try:
        transaction = json.loads(
            plaintext.decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Du lieu sau giai ma khong phai JSON hop le.") from exc

    if not isinstance(transaction, dict):
        raise ValueError("Du lieu giao dich sau giai ma khong hop le.")

    # Kiem tra ma giao dich ben trong va ben ngoai goi ma hoa
    if transaction.get("transaction_id") != transaction_id:
        raise ValueError(
            "Transaction ID ben trong khong khop voi goi ma hoa."
        )

    return transaction


# ==========================================
# 6. KIEM THU PRIVATE KEY SAI
# ==========================================

def test_wrong_private_key(encrypted_package):
    """Kiem tra RSA-OAEP tu choi Private Key khong khop."""

    if not isinstance(encrypted_package, dict):
        raise ValueError("Goi ma hoa khong hop le.")

    encrypted_key = decode_base64(
        encrypted_package["encrypted_key"],
        "encrypted_key",
        512
    )

    fake_private_key = RSA.generate(RSA_BITS)

    rsa_cipher = PKCS1_OAEP.new(
        fake_private_key,
        hashAlgo=SHA256
    )

    try:
        rsa_cipher.decrypt(encrypted_key)

        return {
            "success": False,
            "rejected": False,
            "message": "Canh bao: RSA chap nhan Private Key khong khop."
        }

    except ValueError:
        return {
            "success": True,
            "rejected": True,
            "message": "RSA-OAEP tu choi Private Key khong khop."
        }
