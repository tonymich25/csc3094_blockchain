import time
import hashlib
import statistics
import csv

from Signatures.scheme_registry import scheme_registry
from keystore import KeyStore
from signing import TransactionSigner


def make_payload(i: int, size: int) -> bytes:
    # Deterministic payload: same (i, size) gives same bytes every run
    seed = (str(i) + ":" + str(size)).encode("utf-8")
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:size]


def generate_specs(n_txs: int):
    senders = ["Alice", "Bob", "Charlie", "Dave", "Eve", "Frank"]
    payload_sizes = [1024]

    nonces = {s: 0 for s in senders}
    specs = []

    for i in range(n_txs):
        sender = senders[i % len(senders)]
        nonce = nonces[sender]
        nonces[sender] += 1

        size = payload_sizes[i % len(payload_sizes)]
        payload = make_payload(i, size)

        specs.append((sender, nonce, payload))

    return specs


def build_transactions(specs, algorithms, signer: TransactionSigner):
    txs = []
    for sender, nonce, payload in specs:
        txs.append(signer.sign(sender, nonce, payload, algorithms))
    return txs


def p95(values):
    if not values:
        return None
    s = sorted(values)
    idx = int(0.95 * (len(s) - 1))
    return s[idx]


def measure_verify_and_sigsize(txs):
    per_tx_verify_ns = []
    per_tx_sig_bytes = []

    for tx in txs:
        msg = tx.unsigned_bytes

        tx_verify_ns = 0
        for algo, pk, sig in zip(tx.algorithms, tx.public_keys, tx.signatures):
            scheme = scheme_registry.get(algo)
            if scheme is None:
                raise ValueError("Unknown scheme in tx.algorithms: " + str(algo))

            t0 = time.perf_counter_ns()
            ok = scheme.verify(pk, msg, sig)
            t1 = time.perf_counter_ns()

            if not ok:
                raise RuntimeError("Verify failed: tx_id=" + tx.tx_id + " algo=" + str(algo))

            tx_verify_ns += (t1 - t0)

        per_tx_verify_ns.append(tx_verify_ns)
        per_tx_sig_bytes.append(sum(len(s) for s in tx.signatures))

    return per_tx_verify_ns, per_tx_sig_bytes


def summarize(mode: str, n_txs: int, verify_ns_list, sig_bytes_list):
    verify_ms = [v / 1e6 for v in verify_ns_list]

    return {
        "mode": mode,
        "n_txs": n_txs,
        "verify_ms_mean": statistics.mean(verify_ms),
        "verify_ms_median": statistics.median(verify_ms),
        "verify_ms_p95": p95(verify_ms),
        "sig_bytes_mean": statistics.mean(sig_bytes_list),
        "sig_bytes_median": statistics.median(sig_bytes_list),
    }


def main():
    keys = list(scheme_registry.keys())

    ecdsa_key = next((k for k in keys if k.startswith("ECDSA")), None)
    pq_key = "ML-DSA-44" if "ML-DSA-44" in scheme_registry else None

    if ecdsa_key is None:
        raise SystemExit("Could not find an ECDSA key in scheme_registry")
    if pq_key is None:
        raise SystemExit("Could not find ML-DSA-44 in scheme_registry")

    configs = [
        ("classical", [ecdsa_key]),
        ("pq", [pq_key]),
        ("hybrid", [ecdsa_key, pq_key]),
    ]

    n_txs = 20  # change if you want, larger is smoother
    specs = generate_specs(n_txs)

    keystore = KeyStore(scheme_registry)
    signer = TransactionSigner(scheme_registry, keystore)

    summaries = []

    for mode, algos in configs:
        txs = build_transactions(specs, algos, signer)
        verify_ns_list, sig_bytes_list = measure_verify_and_sigsize(txs)
        s = summarize(mode, n_txs, verify_ns_list, sig_bytes_list)
        summaries.append(s)

        print("\nmode:", mode)
        print("verify ms/tx (mean):", s["verify_ms_mean"])
        print("verify ms/tx (median):", s["verify_ms_median"])
        print("verify ms/tx (p95):", s["verify_ms_p95"])
        print("signature bytes/tx (mean):", s["sig_bytes_mean"])
        print("signature bytes/tx (median):", s["sig_bytes_median"])

    with open("poster_metrics.csv", "w", newline="", encoding="utf-8") as f:
        fieldnames = list(summaries[0].keys())
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(summaries)

    print("\nSaved: poster_metrics.csv")


if __name__ == "__main__":
    main()