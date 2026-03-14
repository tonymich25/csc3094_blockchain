# Signatures/ecdsa.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class ECDSASignature:
    NAME = "ECDSA-secp256k1-SHA256"
    CURVE = "secp256k1"
    HASH = "SHA-256"

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

    # NEW: sign a 32-byte SHA-256 digest without hashing again
    def sign_digest(self, secret_key_bytes, digest32):
        sk = serialization.load_der_private_key(secret_key_bytes, password=None, backend=default_backend())
        return sk.sign(digest32, ec.ECDSA(Prehashed(hashes.SHA256())))

    # NEW: verify a 32-byte SHA-256 digest without hashing again
    def verify_digest(self, public_key_bytes, digest32, signature):
        try:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
            pk.verify(signature, digest32, ec.ECDSA(Prehashed(hashes.SHA256())))
            return True
        except (InvalidSignature, ValueError):
            return False

    # Keep your old methods if you still use them elsewhere
    def sign(self, secret_key_bytes, message):
        sk = serialization.load_der_private_key(secret_key_bytes, password=None, backend=default_backend())
        return sk.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key_bytes, message, signature):
        try:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
            pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False