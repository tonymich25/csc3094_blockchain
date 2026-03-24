import os
import csv
import json
import time
import hashlib
import psutil


from Signatures.scheme_registry import scheme_registry
from Signatures.ecdsa import ECDSASignature
from Signatures.dilithium import DilithiumSignature

from Blockchain.blockchain import Blockchain
from Blockchain.transaction import Transaction
from keystore import KeyStore

ECDSA_KEY = ECDSASignature.NAME
PQC_KEY = DilithiumSignature.NAME


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def now_run_id():
    return time.strftime("%d%m%Y_%H%M%S")


def make_payload(i, size):
    seed = (str(i) + ":" + str(size)).encode("utf-8")
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:size]


def get_process():
    return psutil.Process(os.getpid())


def rss_bytes(proc):
    return int(proc.memory_info().rss)


def cpu_time_seconds(proc):
    t = proc.cpu_times()
    return float(t.user + t.system)


def scheme_sign(scheme, sk_bytes, msg_bytes):
    t0 = time.perf_counter_ns()
    sig = scheme.sign(sk_bytes, msg_bytes)
    t1 = time.perf_counter_ns()
    return sig, (t1 - t0)


def scheme_verify(scheme, pk_bytes, msg_bytes, sig_bytes):
    t0 = time.perf_counter_ns()
    ok = scheme.verify(pk_bytes, msg_bytes, sig_bytes)
    t1 = time.perf_counter_ns()
    return ok, (t1 - t0)


def run_experiment(mode, n_txs, block_size, verify_correctness=True, out_dir=None):
    if mode == "classical":
        algo_list = [ECDSA_KEY]
    elif mode == "pq":
        algo_list = [PQC_KEY]
    elif mode == "hybrid":
        algo_list = [ECDSA_KEY, PQC_KEY]
    else:
        raise ValueError("mode must be: classical, pq, hybrid")

    if n_txs % block_size != 0:
        raise ValueError("n_txs must be a multiple of block_size for this runner")

    if out_dir is None:
        out_dir = os.path.join("../runs", now_run_id() + "_" + mode + "_n" + str(n_txs) + "_bs" + str(block_size))
    ensure_dir(out_dir)

    proc = get_process()
    rss_start = rss_bytes(proc)
    cpu_start = cpu_time_seconds(proc)
    elapsed_start = time.perf_counter()

    keystore = KeyStore(scheme_registry)
    bc = Blockchain(scheme_registry=scheme_registry, block_size=block_size)

    senders = ["Alice", "Bob", "Charlie", "Dave", "Eve", "Frank"]
    nonces = {s: 0 for s in senders}
    payload_sizes = [16, 32, 64, 128, 256]

    # Raw tuples collected during timed window - no dict/JSON overhead
    # (mode, i, sender, nonce, payload_len, algo, sign_ns, verify_ns, sig_len, pk_len)
    raw_sig_results = []
    # (mode, i, tx_id, sender, nonce, payload_len, num_sigs, tx_sign_ns, tx_verify_ns, crypto_overhead)
    raw_tx_results = []
    # (mode, block_index, block_size, commit_ns)
    raw_block_results = []

    total_sign_ns = 0
    total_verify_ns = 0
    total_commit_ns = 0

    batch = []
    transactions = {}  # tx_id -> tx
    block_index = 0

    for i in range(n_txs):
        sender = senders[i % len(senders)]
        nonce = nonces[sender]
        nonces[sender] += 1

        psize = payload_sizes[i % len(payload_sizes)]
        payload = make_payload(i, psize)

        keystore.ensure_sender_keys(sender, algo_list)

        msg = Transaction.canonical_unsigned_bytes(sender, nonce, payload)

        signatures = []
        public_keys = []
        algorithms = []

        tx_sign_ns = 0
        tx_verify_ns = 0

        for algo in algo_list:
            scheme = scheme_registry.get(algo)
            sk = keystore.get_sk(sender, algo)
            pk = keystore.get_pk(sender, algo)

            sig, sign_ns = scheme_sign(scheme, sk, msg)
            ok, verify_ns = scheme_verify(scheme, pk, msg, sig)

            if not ok:
                raise RuntimeError("signature verify failed during run: algo=" + algo + " i=" + str(i))

            signatures.append(sig)
            public_keys.append(pk)
            algorithms.append(algo)

            tx_sign_ns += sign_ns
            tx_verify_ns += verify_ns

            raw_sig_results.append((mode, i, sender, nonce, len(payload), algo, sign_ns, verify_ns, len(sig), len(pk)))

        total_sign_ns += tx_sign_ns
        total_verify_ns += tx_verify_ns

        tx = Transaction(sender, nonce, payload, signatures, public_keys, algorithms)

        tx_crypto_overhead = sum(len(s) for s in signatures) + sum(len(pk) for pk in public_keys)

        raw_tx_results.append((mode, i, tx.tx_id, sender, nonce, len(payload), len(signatures), tx_sign_ns, tx_verify_ns, tx_crypto_overhead))

        batch.append(tx)
        transactions[tx.tx_id] = tx

        if len(batch) == block_size:
            t0 = time.perf_counter_ns()
            bc.commit_block(batch, verify_signatures=False, enforce_block_size=True)
            t1 = time.perf_counter_ns()
            commit_ns = t1 - t0
            total_commit_ns += commit_ns

            raw_block_results.append((mode, block_index, block_size, commit_ns))

            block_index += 1
            batch = []

    elapsed_end = time.perf_counter()
    cpu_end = cpu_time_seconds(proc)
    rss_end = rss_bytes(proc)

    # Outside the timed window

    chain_ok = bc.validate_chain(verify_signatures=verify_correctness)

    elapsed_total = elapsed_end - elapsed_start
    cpu_total = cpu_end - cpu_start
    crypto_seconds_total = (total_sign_ns + total_verify_ns) / 1e9

    summary = {
        "mode": mode,
        "n_txs": n_txs,
        "block_size": block_size,
        "blocks_total_including_genesis": len(bc.chain),
        "validate_chain": bool(chain_ok),
        "elapsed_seconds_total": elapsed_total,
        "sign_seconds_total": total_sign_ns / 1e9,
        "verify_seconds_total": total_verify_ns / 1e9,
        "commit_seconds_total": total_commit_ns / 1e9,
        "crypto_seconds_total": crypto_seconds_total,
        "tps_end_to_end": (n_txs / elapsed_total) if elapsed_total > 0 else None,
        "tps_crypto_only": (n_txs / crypto_seconds_total) if crypto_seconds_total > 0 else None,
        "rss_start_bytes": rss_start,
        "rss_end_bytes": rss_end,
        "rss_delta_bytes": rss_end - rss_start,
        "cpu_start_seconds": cpu_start,
        "cpu_end_seconds": cpu_end,
        "cpu_seconds_total": cpu_total,
        "chain_size_bytes_json": bc.chain_size_bytes(include_transactions=True),
    }

    # convert raw tuples to dicts for CSV
    per_sig_rows = [
        {
            "mode": r[0], "i": r[1], "sender_id": r[2], "nonce": r[3],
            "payload_bytes": r[4], "algorithm": r[5], "sign_time_ns": r[6],
            "verify_time_ns": r[7], "signature_bytes": r[8], "public_key_bytes": r[9],
        }
        for r in raw_sig_results
    ]

    per_tx_rows = [
        {
            "mode": r[0], "i": r[1], "tx_id": r[2], "sender_id": r[3],
            "nonce": r[4], "payload_bytes": r[5], "num_signatures": r[6],
            "sign_time_ns_total": r[7], "verify_time_ns_total": r[8],
            "crypto_overhead_bytes": r[9],
            "tx_json_bytes": len(json.dumps(
                transactions[r[2]].to_dict(),
                sort_keys=True, separators=(",", ":")
            ).encode("utf-8")),
        }
        for r in raw_tx_results
    ]

    per_block_rows = [
        {
            "mode": r[0], "block_index": r[1], "block_size": r[2], "commit_time_ns": r[3],
        }
        for r in raw_block_results
    ]


    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    with open(os.path.join(out_dir, "chain.json"), "w", encoding="utf-8") as f:
        json.dump(bc.to_dict(include_transactions=True), f, indent=2, sort_keys=True)

    with open(os.path.join(out_dir, "per_signature.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(per_sig_rows[0].keys()))
        w.writeheader()
        w.writerows(per_sig_rows)

    with open(os.path.join(out_dir, "per_transaction.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(per_tx_rows[0].keys()))
        w.writeheader()
        w.writerows(per_tx_rows)

    with open(os.path.join(out_dir, "per_block.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(per_block_rows[0].keys()))
        w.writeheader()
        w.writerows(per_block_rows)

    print("saved:", out_dir)
    print("summary:", summary)

    return summary


if __name__ == "__main__":
    run_experiment(mode="pq", n_txs=1000, block_size=50, verify_correctness=True)