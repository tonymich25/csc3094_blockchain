from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class ECDSASignature:
    NAME = "ECDSA-sepc256k1-SHA256"
    ALGORITHM = "ECDSA"
    CURVE = "secp256k1"
    HASH = "SHA-256"

    def generate_keypair(self):
        # returns (secret_key_bytes, public_key_bytes)
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
        sk = serialization.load_der_private_key(
            secret_key_bytes, password=None, backend=default_backend()
        )
        return sk.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key_bytes, message, signature):
        try:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
            pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except ValueError:
            # bad key encoding, etc.
            return False
