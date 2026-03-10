import json
import hashlib

from Signatures.dilithium import DilithiumSignature
from Signatures.ecdsa import ECDSASignature
from Signatures.scheme_registry import scheme_registry
from keystore import KeyStore
from signing import TransactionSigner
from Blockchain.blockchain import Blockchain


ECDSA_KEY = ECDSASignature.NAME
PQC_KEY = DilithiumSignature.NAME


def make_payload(i, size):
    # deterministic bytes, varies with i and size
    seed = (str(i) + ":" + str(size)).encode("utf-8")
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:size]


def run(mode, n_txs=100, block_size=25, verify=True):
    if mode == "classical":
        algo_list = [ECDSA_KEY]
    elif mode == "pq":
        algo_list = [PQC_KEY]
    elif mode == "hybrid":
        algo_list = [ECDSA_KEY, PQC_KEY]
    else:
        raise ValueError("mode must be: classical, pq, hybrid")

    keystore = KeyStore(scheme_registry)
    signer = TransactionSigner(scheme_registry, keystore)
    bc = Blockchain(scheme_registry=scheme_registry, block_size=block_size)

    senders = ["Alice", "Bob", "Charlie", "Dave", "Eve", "Frank"]
    nonces = {s: 0 for s in senders}
    payload_sizes = [16, 32, 64, 128, 256]

    batch = []

    for i in range(n_txs):
        sender = senders[i % len(senders)]
        nonce = nonces[sender]
        nonces[sender] += 1

        size = payload_sizes[i % len(payload_sizes)]
        payload = make_payload(i, size)

        tx = signer.sign(sender, nonce, payload, algo_list)
        batch.append(tx)

        if len(batch) == block_size:
            bc.commit_block(batch, verify_signatures=verify, enforce_block_size=True)
            batch = []

    # last partial block (if n_txs not divisible by block_size)
    if batch:
        bc.commit_block(batch, verify_signatures=verify, enforce_block_size=False)

    ok = bc.validate_chain(verify_signatures=verify)

    print("mode:", mode)
    print("txs:", n_txs)
    print("block_size:", block_size)
    print("blocks:", len(bc.chain))
    print("validate_chain:", ok)
    print("chain_size_bytes:", bc.chain_size_bytes(include_transactions=True))

    with open("chain_" + mode + ".json", "w", encoding="utf-8") as f:
        json.dump(bc.to_dict(include_transactions=True), f, indent=2, sort_keys=True)

    return bc


if __name__ == "__main__":
    # pick one mode to start
    run(mode="hybrid", n_txs=100, block_size=25, verify=True)