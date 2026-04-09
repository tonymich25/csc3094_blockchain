import nacl.signing
import nacl.exceptions


class EdDSASignature:
    NAME = "EdDSA-Ed25519"
    ALGORITHM = "EdDSA"
    CURVE = "Ed25519"
    STANDARD = "FIPS 186-5"
    SECURITY_LEVEL = 1  # ~128-bit classical / not quantum-safe

    def __init__(self):
        self._sk_cache = {}

    def generate_keypair(self):
        sk = nacl.signing.SigningKey.generate()
        sk_bytes = bytes(sk)                          # 32 bytes
        pk_bytes = bytes(sk.verify_key)               # 32 bytes
        return sk_bytes, pk_bytes

    def sign(self, secret_key_bytes, message):
        sk = self._sk_cache.get(secret_key_bytes)
        if sk is None:
            sk = nacl.signing.SigningKey(secret_key_bytes)
            self._sk_cache[secret_key_bytes] = sk
        signed = sk.sign(message)
        return signed.signature                       # 64 bytes

    def verify(self, public_key_bytes, message, signature):
        try:
            vk = nacl.signing.VerifyKey(public_key_bytes)
            vk.verify(message, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except Exception:
            return False