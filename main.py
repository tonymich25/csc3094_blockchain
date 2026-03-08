from Signatures.scheme_registry import scheme_registry
from keystore import KeyStore
from signing import TransactionSigner

keystore = KeyStore(scheme_registry)
builder = TransactionSigner(scheme_registry, keystore)

sender = "Alice"
payload = b"hello"

ECDSA_KEY = "ECDSA-secp256k1-SHA256"
PQC_KEY = "ML-DSA-44"

tx1 = builder.sign(sender, 0, payload, [ECDSA_KEY])
tx2 = builder.sign(sender, 1, payload, [PQC_KEY])
tx3 = builder.sign(sender, 2, payload, [ECDSA_KEY, PQC_KEY])

print(tx1)
print(tx2)
print(tx3)