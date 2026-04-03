import hashlib
import os
from concurrent.futures import ProcessPoolExecutor

from coincurve import PrivateKey, PublicKey


# Must be module-level (not a method) so ProcessPoolExecutor can pickle it
def _verify_single(args):
    pk_bytes, msg_hash, signature = args
    try:
        return PublicKey(pk_bytes).verify(signature, msg_hash, hasher=None)
    except Exception:
        return False


class ECDSASignature:
    NAME = "ECDSA-secp256k1-SHA256"
    ALGORITHM = "ECDSA"
    CURVE = "secp256k1"
    HASH = "SHA-256"

    # Below this many signatures, multiprocessing spawn overhead costs more than it saves.
    # GLV and precomputed-G table optimisations still run inside every verify() call
    # regardless of this threshold — they are not affected by it.
    BATCH_THRESHOLD = 64

    def __init__(self):
        self._pk_cache = {}
        self._sk_cache = {}

    def generate_keypair(self):
        sk = PrivateKey()
        sk_bytes = sk.secret  # 32 bytes (raw private key)
        pk_bytes = sk.public_key.format(compressed=False)  # 65 bytes (uncompressed)
        return sk_bytes, pk_bytes

    def _hash_message(self, message: bytes) -> bytes:
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

    def batch_verify(self, items, workers=None):
        """
        Verify multiple signatures in parallel across CPU cores.

        items:   list of (pk_bytes, message, signature)
        workers: number of worker processes (defaults to os.cpu_count())

        Returns (all_valid: bool, failed_indices: list[int])

        Note: GLV endomorphism and precomputed generator tables (optimisations 1 & 2)
        are already active inside each _verify_single call via libsecp256k1 — this
        method adds optimisation 3 by distributing work across cores.
        """
        if not items:
            return True, []

        # Pre-hash all messages once here rather than once per worker
        args = [(pk, hashlib.sha256(msg).digest(), sig) for pk, msg, sig in items]

        if len(items) < self.BATCH_THRESHOLD:
            results = [_verify_single(a) for a in args]
        else:
            workers = workers or os.cpu_count() or 4
            with ProcessPoolExecutor(max_workers=workers) as ex:
                results = list(ex.map(_verify_single, args))

        failed = [i for i, ok in enumerate(results) if not ok]
        return len(failed) == 0, failed