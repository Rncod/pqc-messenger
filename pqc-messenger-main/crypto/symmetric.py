# crypto/symmetric.py

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Dérive une clé AES-256 (32 octets) à partir du shared_secret issu de ML-KEM.
    Ici on tronque/pad simplement à 32 octets.
    """
    if len(shared_secret) >= 32:
        return shared_secret[:32]
    return (shared_secret + b"\x00" * 32)[:32]


def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Chiffre 'plaintext' avec AES-GCM.
    Retourne (nonce, ciphertext, tag).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return nonce, ciphertext, tag


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Déchiffre les données AES-GCM. Lève une exception si données modifiées.
    """
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, ct_with_tag, associated_data=None)
    return plaintext
