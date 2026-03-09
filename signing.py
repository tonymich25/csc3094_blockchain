from Blockchain.transaction import Transaction


class TransactionSigner:
    def __init__(self, scheme_registry, keystore):
        self.scheme_registry = scheme_registry
        self.keystore = keystore

    def sign(self, sender_id, nonce, payload: bytes, algorithms):
        algorithms = list(algorithms)

        # Ensure keys exist for this sender for all requested schemes
        self.keystore.ensure_sender_keys(sender_id, algorithms)

        # Single source of truth for what gets signed
        msg = Transaction.canonical_unsigned_bytes(sender_id, nonce, payload)

        signatures = []
        public_keys = []

        for algo in algorithms:
            scheme = self.scheme_registry.get(algo)
            if scheme is None:
                raise ValueError("Unknown scheme: " + str(algo))

            sk, pk = self.keystore.get_keypair(sender_id, algo)
            sig = scheme.sign(sk, msg)

            signatures.append(sig)
            public_keys.append(pk)

        return Transaction(
            sender_id=sender_id,
            nonce=nonce,
            payload=payload,
            signatures=signatures,
            public_keys=public_keys,
            algorithms=algorithms,
        )