import hashlib
import json
import time


class Block:
    def __init__(self, index, transactions, previous_hash, timestamp=None):
        self.index = int(index)
        self.timestamp = int(time.time() if timestamp is None else timestamp)
        self.previous_hash = str(previous_hash)

        self.transactions = list(transactions)

        self._validate()

        self.tx_ids = [tx.tx_id for tx in self.transactions]
        self.block_hash = self.compute_hash()

    def _validate(self):
        if self.index < 0:
            raise ValueError("index must be non-negative")

        if not isinstance(self.previous_hash, str) or not self.previous_hash:
            raise ValueError("previous_hash must be a non-empty string")

        if not isinstance(self.transactions, list):
            raise TypeError("transactions must be a list")

        for tx in self.transactions:
            if not hasattr(tx, "tx_id") or not isinstance(tx.tx_id, str) or not tx.tx_id:
                raise TypeError("each transaction must have a non-empty string tx_id")

    def header_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "tx_ids": self.tx_ids,
        }

    def compute_hash(self):
        header_bytes = json.dumps(
            self.header_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(header_bytes).hexdigest()

    def validate_self(self):
        current_tx_ids = [tx.tx_id for tx in self.transactions]
        if current_tx_ids != self.tx_ids:
            return False
        return self.compute_hash() == self.block_hash

    def to_dict(self, include_transactions=True):
        d = {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "tx_ids": self.tx_ids,
            "block_hash": self.block_hash,
        }

        if include_transactions:
            d["transactions"] = [tx.to_dict() for tx in self.transactions]

        return d