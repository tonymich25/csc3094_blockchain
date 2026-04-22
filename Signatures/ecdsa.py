import hashlib
from coincurve import PrivateKey, PublicKey


class ECDSASignature:
    NAME = "ECDSA-secp256k1-SHA256"
    ALGORITHM = "ECDSA"
    CURVE = "secp256k1"
    HASH = "SHA-256"

    def __init__(self):
        self._pk_cache = {}
        self._sk_cache = {}

    def generate_keypair(self):
        sk = PrivateKey()
        sk_bytes = sk.secret  # 32 bytes (raw private key)
        pk_bytes = sk.public_key.format(compressed=True)  # 65 bytes (uncompressed)
        return sk_bytes, pk_bytes

    def _hash_message(self, message):
        return hashlib.sha256(message).digest()

    def sign(self, secret_key_bytes, message):
        sk = self._sk_cache.get(secret_key_bytes)
        if sk is None:
            sk = PrivateKey(secret_key_bytes)
            self._sk_cache[secret_key_bytes] = sk
        return sk.sign(self._hash_message(message), hasher=None)  # 64-byte compact (r||s)

    def verify(self, public_key_bytes, message, signature):
        try:
            pk = self._pk_cache.get(public_key_bytes)
            if pk is None:
                pk = PublicKey(public_key_bytes)
                self._pk_cache[public_key_bytes] = pk
        except ValueError:
            return False
        return pk.verify(signature, self._hash_message(message), hasher=None)