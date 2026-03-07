import json
from transaction import Transaction

def canonical_unsigned_bytes(sender_id, nonce, payload):
    data = {
        "sender_id": sender_id,
        "nonce": nonce,
        "payload": payload.hex(),
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sign_transaction(sender_id, nonce, payload, algorithms, scheme_registry, keystore):
    keystore.ensure_sender(sender_id, algorithms)
    msg = canonical_unsigned_bytes(sender_id, nonce, payload)

    signatures = []
    public_keys = []

    for algo in algorithms:
        sk, pk = keystore.get(sender_id, algo)
        sig = scheme_registry[algo].sign(sk, msg)
        signatures.append(sig)
        public_keys.append(pk)

    return Transaction(
        sender_id=sender_id,
        nonce=nonce,
        payload=payload,
        signatures=signatures,
        public_keys=public_keys,
        algorithms=list(algorithms),
    )