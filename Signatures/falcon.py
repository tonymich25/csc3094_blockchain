import os
import sys

if sys.platform == "win32":
    dll_dir = r"C:\Users\mtony\_oqs\bin"
    if os.path.isdir(dll_dir):
        os.environ["PATH"] = dll_dir + os.pathsep + os.environ.get("PATH", "")
        os.add_dll_directory(dll_dir)

import oqs


class FalconSignature:
    NAME = "Falcon-512"
    ALGORITHM = "Falcon"
    STANDARD = "FIPS 206 (FN-DSA)"
    SECURITY_LEVEL = 1  # ~128-bit classical / ~64-bit quantum

    def generate_keypair(self):
        with oqs.Signature(self.NAME) as s:
            public_key = s.generate_keypair()
            secret_key = s.export_secret_key()
        return secret_key, public_key

    def sign(self, secret_key, message):
        with oqs.Signature(self.NAME, secret_key) as s:
            return s.sign(message)

    def verify(self, public_key, message, signature):
        try:
            with oqs.Signature(self.NAME) as v:
                return v.verify(message, signature, public_key)
        except Exception:
            return False