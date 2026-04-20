import os
import hashlib
import base64
from typing import Dict, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def derive_master_key(password: str, salt: Union[str, bytes]) -> bytes:
    if isinstance(salt, str):
        salt = base64.b64decode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password.encode())


def generate_salt() -> str:
    salt = os.urandom(32)
    return base64.b64encode(salt).decode()


def encrypt_file(plaintext: bytes, master_key: bytes) -> Dict[str, Union[bytes, str]]:
    fek = os.urandom(32)
    nonce = os.urandom(12)

    aesgcm = AESGCM(fek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    wrap_nonce = os.urandom(12)
    wrap_aesgcm = AESGCM(master_key)
    wrapped_fek = wrap_aesgcm.encrypt(wrap_nonce, fek, None)

    checksum = hashlib.sha256(plaintext).hexdigest()

    return {
        'ciphertext': ciphertext,
        'nonce': base64.b64encode(nonce).decode(),
        'wrapped_fek': base64.b64encode(wrapped_fek).decode(),
        'wrap_nonce': base64.b64encode(wrap_nonce).decode(),
        'checksum': checksum,
    }


def decrypt_file(
    ciphertext: bytes,
    nonce: Union[str, bytes],
    wrapped_fek: Union[str, bytes],
    wrap_nonce: Union[str, bytes],
    master_key: bytes
) -> bytes:
    if isinstance(nonce, str):
        nonce = base64.b64decode(nonce)
    if isinstance(wrapped_fek, str):
        wrapped_fek = base64.b64decode(wrapped_fek)
    if isinstance(wrap_nonce, str):
        wrap_nonce = base64.b64decode(wrap_nonce)

    wrap_aesgcm = AESGCM(master_key)
    fek = wrap_aesgcm.decrypt(wrap_nonce, wrapped_fek, None)

    aesgcm = AESGCM(fek)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext
