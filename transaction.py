import json


class Transaction:
    def __init__(self, sender_id, nonce, payload, signatures, public_keys, algorithms):
        self.sender_id = sender_id
        self.nonce = nonce
        self.payload = payload
        self.signatures = signatures
        self.public_keys = public_keys
        self.algorithms = algorithms

        self._validate()
        self._unsigned_bytes = self._canonical_unsigned_bytes()

    def _validate(self):
        if not isinstance(self.sender_id, str) or not self.sender_id:
            raise ValueError("sender_id must be a non-empty string")

        if not isinstance(self.nonce, int):
            raise TypeError("nonce must be an int")

        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be bytes")

        if not isinstance(self.signatures, list) or not all(isinstance(s, bytes) for s in self.signatures):
            raise TypeError("signatures must be list[bytes]")

        if not isinstance(self.public_keys, list) or not all(isinstance(pk, bytes) for pk in self.public_keys):
            raise TypeError("public_keys must be list[bytes]")

        if not isinstance(self.algorithms, list) or not all(isinstance(a, str) for a in self.algorithms):
            raise TypeError("algorithms must be list[str]")

        if len(self.signatures) != len(self.public_keys):
            raise ValueError("signatures and public_keys must match")

        if len(self.signatures) != len(self.algorithms):
            raise ValueError("signatures and algorithms must match")

        if len(self.signatures) == 0:
            raise ValueError("at least one signature required")

    def _canonical_unsigned_bytes(self):
        """
            {"sender_id":"Alice","nonce":3,"payload":"706179..."}
        """
        data = {
            "sender_id": self.sender_id,
            "nonce": self.nonce,
            "payload": self.payload.hex(),
        }
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

    @property
    def unsigned_bytes(self):
        return self._unsigned_bytes