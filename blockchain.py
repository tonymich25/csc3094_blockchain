import json
import time


class Blockchain:
    """
    Minimal blockchain manager for your signature testbed.

    Responsibilities:
    - store blocks in order
    - create genesis block
    - create new blocks from transaction batches (block factory)
    - validate chaining + block integrity + tx signatures via scheme_registry

    scheme_registry format:
      {
        "Ed25519": object_with_verify(pk: bytes, msg: bytes, sig: bytes) -> bool,
        "Dilithium2": object_with_verify(...),
        ...
      }
    """

    def __init__(self, scheme_registry: dict, block_size: int = 50, genesis_previous_hash: str = "0"):

        self.scheme_registry = scheme_registry
        self.block_size = int(block_size)
        if self.block_size <= 0:
            raise ValueError("block_size must be > 0")

        self.chain = []

        # Genesis block
        genesis = Block(
            index=0,
            transactions=[],
            previous_hash=str(genesis_previous_hash),
            timestamp=int(time.time()),
        )
        self.chain.append(genesis)

    @property
    def last_block(self):
        return self.chain[-1]

    def commit_block(self, transactions: list, enforce_block_size: bool = True):
        """
        Create a new block from a batch of transactions, validate it, then append it.
        """
        if not isinstance(transactions, list):
            raise TypeError("transactions must be a list")

        if enforce_block_size and len(transactions) != self.block_size:
            raise ValueError(f"expected exactly {self.block_size} transactions, got {len(transactions)}")

        block = Block(
            index=len(self.chain),
            transactions=transactions,
            previous_hash=self.last_block.block_hash,
            timestamp=int(time.time()),
        )

        self.validate_block(block, expected_previous_hash=self.last_block.block_hash)
        self.chain.append(block)
        return block

    def validate_block(self, block, expected_previous_hash: str):
        # 1) Chain link
        if block.previous_hash != expected_previous_hash:
            raise ValueError("invalid previous_hash link")

        # 2) Block integrity (tx_ids and block_hash)
        if not block.validate_self():
            raise ValueError("block integrity check failed")

        # 3) Validate tx signatures
        for tx in block.transactions:
            self.validate_transaction(tx)

        return True

    def validate_transaction(self, tx):
        # Transaction object already validates on init, but keep a safety check here
        if len(tx.signatures) != len(tx.public_keys) or len(tx.signatures) != len(tx.algorithms):
            raise ValueError("tx signatures/public_keys/algorithms length mismatch")

        msg = tx.unsigned_bytes

        for algo, pk, sig in zip(tx.algorithms, tx.public_keys, tx.signatures):
            scheme = self.scheme_registry.get(algo)
            if scheme is None:
                raise ValueError(f"unknown algorithm: {algo}")

            if not scheme.verify(pk, msg, sig):
                raise ValueError(f"invalid signature for tx_id={tx.tx_id} algo={algo}")

        return True

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            prev = self.chain[i - 1]
            cur = self.chain[i]
            self.validate_block(cur, expected_previous_hash=prev.block_hash)
        return True

    def chain_size_bytes(self, include_transactions: bool = True) -> int:
        # Deterministic size proxy for "ledger growth"
        chain_dict = [b.to_dict(include_transactions=include_transactions) for b in self.chain]
        b = json.dumps(chain_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return len(b)