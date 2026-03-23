from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class ECDSASignature:
    NAME = "ECDSA-secp256k1-SHA256"
    ALGORITHM = "ECDSA"
    CURVE = "secp256k1"
    HASH = "SHA-256"

    def __init__(self):
        self._pk_cache = {}
        self._sk_cache = {}

    def generate_keypair(self):
        sk = ec.generate_private_key(ec.SECP256K1(), default_backend())

        sk_bytes = sk.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        pk_bytes = sk.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        return sk_bytes, pk_bytes

    def sign(self, secret_key_bytes, message):
        sk = self._sk_cache.get(secret_key_bytes)
        if sk is None:
            sk = serialization.load_der_private_key(
                secret_key_bytes, password=None, backend=default_backend()
            )
            self._sk_cache[secret_key_bytes] = sk
        return sk.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key_bytes, message, signature):
        print(f"cache size: {len(self._pk_cache)}, hit: {public_key_bytes in self._pk_cache}")

        try:
            pk = self._pk_cache.get(public_key_bytes)
            if pk is None:
                pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
                self._pk_cache[public_key_bytes] = pk
            pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except ValueError:
            return False