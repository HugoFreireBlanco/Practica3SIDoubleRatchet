import os
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

COMUNICATION_PORT = 6027
DEFAULT_IP = "127.0.0.1"

# Lock for thread-safe printing
print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    """Thread-safe print function to avoid mixing output from different threads"""
    with print_lock:
        print(*args, **kwargs)

# Precoded 128 bit root key (fixed value shared between sender and receiver)
ROOT_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef")

BUFFER_SIZE = 4096

def _generate_df_private_key():
    return X25519PrivateKey.generate()

def _generate_df_public_key(private_key : X25519PrivateKey):
    return private_key.public_key()

def serialize_public_key(public_key : X25519PublicKey):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def deserialize_public_key(public_key_bytes : bytes) -> X25519PublicKey: 
    return X25519PublicKey.from_public_bytes(public_key_bytes)

def send_public_key(socket, public_key : X25519PublicKey):
    socket.send(serialize_public_key(public_key))

def receive_public_key(socket):
    key_bytes = socket.recv(32)
    return deserialize_public_key(key_bytes)

def generate_df_key_pair():
    private_key = _generate_df_private_key()
    return private_key, _generate_df_public_key(private_key)

def obtain_shared_secret(private_key, public_key):
    return private_key.exchange(public_key)

def KDF_RK(rk: bytes, dh_out: bytes):
    """
    Deriva una nueva root key y una nueva chain key a partir del root key actual y el DH output.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,        # 32 bytes para root key + 32 bytes para chain key
        salt=rk,          # salt = root key actual
        info=b"DoubleRatchet_RK",  # aplicación específica
    )
    output = hkdf.derive(dh_out)
    new_root_key = output[:16]
    new_chain_key = output[16:]
    return new_root_key, new_chain_key

def KDF_CK(ck: bytes):
    """
    Ratchet simétrico de la chain key.
    Devuelve: message key y siguiente chain key.
    """
    # message key
    h = hmac.HMAC(ck, hashes.SHA256())
    h.update(b"\x01")
    mk = h.finalize()

    # next chain key
    h2 = hmac.HMAC(ck, hashes.SHA256())
    h2.update(b"\x02")
    next_ck = h2.finalize()

    return mk, next_ck


def encrypt(mk : bytes, plaintext : bytes , asociated_data : bytes):
    nonce = os.urandom(12) # este es el tamano recomendado para AESGCM
    cipher = AESGCM(mk)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=asociated_data)
    return nonce + ciphertext

def decrypt(mk: bytes, cyphertext: bytes, associated_data: bytes):
    nonce = cyphertext[:12]       # extraemos los primeros 12 bytes como nonce
    ciphertext = cyphertext[12:]  # el resto es el ciphertext
    aesgcm = AESGCM(mk)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext