import os
import csv
import json
import time
import hashlib

try:
    import psutil
except Exception:
    psutil = None

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
    if psutil is None:
        return None
    try:
        return psutil.Process(os.getpid())
    except Exception:
        return None


def rss_bytes(proc):
    if proc is None:
        return None
    try:
        return int(proc.memory_info().rss)
    except Exception:
        return None


def cpu_time_seconds(proc):
    if proc is None:
        return None
    try:
        t = proc.cpu_times()
        return float(t.user + t.system)
    except Exception:
        return None


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
    wall_start = time.perf_counter()

    keystore = KeyStore(scheme_registry)
    bc = Blockchain(scheme_registry=scheme_registry, block_size=block_size)

    senders = ["Alice", "Bob", "Charlie", "Dave", "Eve", "Frank"]
    nonces = {s: 0 for s in senders}
    payload_sizes = [16, 32, 64, 128, 256]

    per_sig_rows = []
    per_tx_rows = []

    total_sign_ns = 0
    total_verify_ns = 0

    batch = []

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

            per_sig_rows.append({
                "mode": mode,
                "i": i,
                "sender_id": sender,
                "nonce": nonce,
                "payload_bytes": len(payload),
                "algorithm": algo,
                "sign_time_ns": sign_ns,
                "verify_time_ns": verify_ns,
                "signature_bytes": len(sig),
                "public_key_bytes": len(pk),
            })

        total_sign_ns += tx_sign_ns
        total_verify_ns += tx_verify_ns

        tx = Transaction(sender, nonce, payload, signatures, public_keys, algorithms)

        tx_crypto_overhead = sum(len(s) for s in signatures) + sum(len(pk) for pk in public_keys)
        tx_json_bytes = len(json.dumps(tx.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8"))

        per_tx_rows.append({
            "mode": mode,
            "i": i,
            "tx_id": tx.tx_id,
            "sender_id": sender,
            "nonce": nonce,
            "payload_bytes": len(payload),
            "num_signatures": len(signatures),
            "sign_time_ns_total": tx_sign_ns,
            "verify_time_ns_total": tx_verify_ns,
            "crypto_overhead_bytes": tx_crypto_overhead,
            "tx_json_bytes": tx_json_bytes,
        })

        batch.append(tx)

        if len(batch) == block_size:
            bc.commit_block(batch, verify_signatures=verify_correctness, enforce_block_size=True)
            batch = []

    chain_ok = bc.validate_chain(verify_signatures=verify_correctness)

    wall_end = time.perf_counter()
    cpu_end = cpu_time_seconds(proc)
    rss_end = rss_bytes(proc)

    wall_total = wall_end - wall_start

    summary = {
        "mode": mode,
        "n_txs": n_txs,
        "block_size": block_size,
        "blocks_total_including_genesis": len(bc.chain),
        "validate_chain": bool(chain_ok),
        "wall_seconds_total": wall_total,
        "sign_seconds_total": total_sign_ns / 1e9,
        "verify_seconds_total": total_verify_ns / 1e9,
        "tps_end_to_end_wall": (n_txs / wall_total) if wall_total > 0 else None,
        "rss_start_bytes": rss_start,
        "rss_end_bytes": rss_end,
        "cpu_start_seconds": cpu_start,
        "cpu_end_seconds": cpu_end,
        "chain_size_bytes_json": bc.chain_size_bytes(include_transactions=True),
    }

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

    print("saved:", out_dir)
    print("summary:", summary)

    return summary


if __name__ == "__main__":
    run_experiment(mode="classical", n_txs=1000, block_size=50, verify_correctness=True)