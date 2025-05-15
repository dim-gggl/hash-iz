import os
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PBKDF2_ITERATIONS = 100_000

def derive_keys(username: str, password: str, salt: bytes = None) -> tuple[bytes, bytes, bytes]:
    """
    Dérive une clé de chiffrement AES-256 et un hash de vérification à partir 
    du couple (nom d'utilisateur, mot de passe) et d'un sel.
    Retourne un tuple (salt, enc_key, auth_key):
      - salt (16 octets)
      - enc_key: clé AES 256 bits (32 octets)
      - auth_key: clé/valeur de vérification (32 octets) pour le mot de passe
    """
    if salt is None:
        salt = os.urandom(16)

    user_pass = f"{username}:{password}".encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key_material = kdf.derive(user_pass)
    enc_key = key_material[:32]
    auth_key = key_material[32:]

    return salt, enc_key, auth_key

def verify_password(username: str, password: str, salt: bytes, stored_auth_key: bytes) -> bool:
    """
    Vérifie qu'un mot de passe est correct en comparant la valeur dérivée (auth_key) 
    avec celle stockée.
    Retourne True si le mot de passe est valide, False sinon.
    """

    try:
        _, _, auth_key = derive_keys(username, password, salt)
    except Exception:
        return False
    return hmac.compare_digest(stored_auth_key, auth_key)

def encrypt_password(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    """
    Chiffre un mot de passe en clair avec AES-256-GCM.
    - key: clé de 32 octets (256 bits) pour AES.
    - plaintext: le mot de passe en clair.
    Retourne (nonce, encrypted_data) où:
      - nonce (12 octets) est aléatoire,
      - encrypted_data contient le texte chiffré + le tag d'authentification GCM.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce, ciphertext

def decrypt_password(key: bytes, nonce: bytes, encrypted_data: bytes) -> str:
    """
    Déchiffre un mot de passe chiffré avec AES-256-GCM.
    - key: clé de 32 octets utilisée pour le chiffrement.
    - nonce: nonce de 12 octets utilisé lors du chiffrement.
    - encrypted_data: texte chiffré + tag GCM.
    Retourne le mot de passe en clair (ou lève une exception si échec).
    """
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, encrypted_data, None)
    return data.decode('utf-8')
