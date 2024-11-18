# turboEncryption.py
# @package   5GturboAPI
# @author    Samy Younsi - NeroTeam Security Labs <samy@neroteam.com>
# @license   Proprietary License - All Rights Reserved
# @docs      https://neroteam.com/blog/

import json
import base64
import secrets
import hashlib
import hmac
import binascii
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


def createAesccm(key, tag_size):
    return AESCCM(key, tag_size // 8)


def decodeInput(input_data):
    salt = base64.b64decode(input_data["salt"])
    key_size = input_data["ks"]
    tag_size = input_data["ts"]
    iterations = input_data["iter"]
    ct = base64.b64decode(input_data["ct"])[: -tag_size // 8]
    tag = base64.b64decode(input_data["ct"])[-tag_size // 8 :]
    iv = base64.b64decode(input_data["iv"])
    adata = input_data["adata"].encode()
    return salt, key_size, tag_size, iterations, ct, tag, iv, adata


def decrypt(dk, input_data):
    input_data = json.loads(input_data)
    if input_data:
        try:
            salt, key_size, tag_size, iterations, ct, tag, iv, adata = decodeInput(
                input_data
            )
            key = deriveKey(dk, salt, iterations, key_size)
            aesccm = createAesccm(key, tag_size)
            ct_with_tag = ct + tag
            plaintext = aesccm.decrypt(iv, ct_with_tag, adata)
            return plaintext.decode("utf-8")
        except InvalidTag:
            return "Decryption failed: Invalid authentication tag"
        except Exception as e:
            return f"Decryption failed: {str(e)}"


def deriveKey(password, salt, iterations, key_size):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size // 8,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    return key


def encrypt(dk, data_to_encrypt):
    try:
        input_data = {
            "v": 1,
            "iter": 1000,
            "ks": 128,
            "ts": 64,
            "adata": "",
            "cipher": "aes",
        }
        key_size = input_data["ks"]
        tag_size = input_data["ts"]
        salt = secrets.token_bytes(8)
        input_data["salt"] = base64.b64encode(salt).decode()

        key = deriveKey(dk, salt, input_data["iter"], key_size)
        iv = secrets.token_bytes(11)
        input_data["iv"] = base64.b64encode(iv).decode()
        input_data["mode"] = "ccm"

        aesccm = createAesccm(key, tag_size)
        ciphertext = aesccm.encrypt(
            iv, data_to_encrypt.encode(), input_data["adata"].encode()
        )
        ct, tag = ciphertext[: -tag_size // 8], ciphertext[-tag_size // 8 :]
        input_data["ct"] = base64.b64encode(ct + tag).decode()

        return json.dumps(input_data, separators=(",", ":"))
    except Exception as e:
        return f"Encryption failed: {str(e)}"


def generateAppDeriveKey(userpwd, salt_hex, iterations=1000, key_size=128):
    salt = binascii.unhexlify(salt_hex)
    key = deriveKey(userpwd, salt, iterations, key_size)
    dk_hex = binascii.hexlify(key).decode()
    return dk_hex


def hexHmacSha256(key, msg):
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def hexSha256(msg):
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()
