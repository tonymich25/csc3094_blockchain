import json
import time
from Blockchain.block import Block


class Blockchain:
    def __init__(self, scheme_registry=None, block_size=50, genesis_previous_hash=None):
        self.scheme_registry = scheme_registry or {}

        self.block_size = int(block_size)
        if self.block_size <= 0:
            raise ValueError("block_size must be > 0")

        self.chain = []

        prev = genesis_previous_hash
        if prev is None:
            prev = "0" * 64

        genesis = Block(index=0, transactions=[], previous_hash=prev, timestamp=int(time.time()))
        self.chain.append(genesis)

    @property
    def head(self):
        return self.chain[-1]

    def commit_block(self, transactions, timestamp=None, verify_signatures=False, enforce_block_size=False):
        transactions = list(transactions)

        if enforce_block_size and len(transactions) != self.block_size:
            raise ValueError("expected exactly " + str(self.block_size) + " transactions, got " + str(len(transactions)))

        block = Block(
            index=len(self.chain),
            transactions=transactions,
            previous_hash=self.head.block_hash,
            timestamp=int(time.time() if timestamp is None else timestamp),
        )

        self._validate_block(block, expected_previous_hash=self.head.block_hash, verify_signatures=verify_signatures)
        self.chain.append(block)
        return block

    def _validate_block(self, block, expected_previous_hash, verify_signatures=False):
        if block.previous_hash != expected_previous_hash:
            raise ValueError("Invalid previous_hash link")

        if not block.validate_self():
            raise ValueError("Block integrity check failed")

        if verify_signatures:
            self._batch_validate_transactions(block.transactions)

    def _batch_validate_transactions(self, transactions):
        """
        Collect all signatures across all transactions in the block, grouped by
        algorithm, then verify each group in one batch_verify call.

        For schemes that don't implement batch_verify (e.g. Dilithium), falls back
        to individual verification automatically — no changes needed to those schemes.
        """
        items_by_algo = {}
        index_map = {}  # algo -> list of tx_id, for error reporting on failure

        for tx in transactions:
            msg = tx.unsigned_bytes

            if len(tx.signatures) != len(tx.public_keys) or len(tx.signatures) != len(tx.algorithms):
                raise ValueError("Transaction signature/public_key/algorithm mismatch")

            for algo, pk, sig in zip(tx.algorithms, tx.public_keys, tx.signatures):
                if algo not in items_by_algo:
                    items_by_algo[algo] = []
                    index_map[algo] = []
                items_by_algo[algo].append((pk, msg, sig))
                index_map[algo].append(tx.tx_id)

        for algo, items in items_by_algo.items():
            scheme = self.scheme_registry.get(algo)
            if scheme is None:
                raise ValueError("Unknown signature algorithm: " + str(algo))

            if hasattr(scheme, "batch_verify"):
                all_valid, failed = scheme.batch_verify(items)
                if not all_valid:
                    bad_tx_ids = [index_map[algo][i] for i in failed]
                    raise ValueError(
                        "Batch verification failed for "
                        + str(len(failed))
                        + " signature(s), algo="
                        + algo
                        + ", tx_ids="
                        + str(bad_tx_ids)
                    )
            else:
                # Fallback for schemes without batch_verify (e.g. Dilithium)
                for (pk, msg, sig), tx_id in zip(items, index_map[algo]):
                    if not scheme.verify(pk, msg, sig):
                        raise ValueError("Invalid signature: tx_id=" + tx_id + " algo=" + str(algo))

    def _validate_transaction(self, tx):
        msg = tx.unsigned_bytes

        if len(tx.signatures) != len(tx.public_keys) or len(tx.signatures) != len(tx.algorithms):
            raise ValueError("Transaction signature/public_key/algorithm mismatch")

        for algo, pk, sig in zip(tx.algorithms, tx.public_keys, tx.signatures):
            scheme = self.scheme_registry.get(algo)
            if scheme is None:
                raise ValueError("Unknown signature algorithm: " + str(algo))

            if not scheme.verify(pk, msg, sig):
                raise ValueError("Invalid signature: tx_id=" + tx.tx_id + " algo=" + str(algo))

        return True

    def validate_chain(self, verify_signatures=True):
        if not self.chain[0].validate_self():
            return False

        for i in range(1, len(self.chain)):
            prev = self.chain[i - 1]
            cur = self.chain[i]
            try:
                self._validate_block(cur, expected_previous_hash=prev.block_hash, verify_signatures=verify_signatures)
            except ValueError:
                return False
        return True

    def to_dict(self, include_transactions=True):
        return {
            "block_size": self.block_size,
            "blocks": [b.to_dict(include_transactions=include_transactions) for b in self.chain],
        }

    def chain_size_bytes(self, include_transactions=True):
        chain_dict = [b.to_dict(include_transactions=include_transactions) for b in self.chain]
        b = json.dumps(chain_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return len(b)