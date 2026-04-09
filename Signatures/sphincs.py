import oqs

class SPHINCSSignature:
    NAME = "SLH_DSA_PURE_SHA2_128S"
    ALGORITHM = "SPHINCS+"
    STANDARD = "FIPS 205 (SLH-DSA)"
    SECURITY_LEVEL = 1

    def __init__(self):
        self._signers = {}
        self._verifier = oqs.Signature(self.NAME)

    def generate_keypair(self):
        with oqs.Signature(self.NAME) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
        return sk, pk

    def sign(self, secret_key, message):
        if secret_key not in self._signers:
            self._signers[secret_key] = oqs.Signature(self.NAME, secret_key)
        return self._signers[secret_key].sign(message)

    def verify(self, public_key, message, signature):
        try:
            return self._verifier.verify(message, signature, public_key)
        except Exception:
            return False