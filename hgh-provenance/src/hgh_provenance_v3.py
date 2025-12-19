#!/usr/bin/env python3
import os, json, hashlib, hmac, argparse, unicodedata
from typing import Dict, List, Tuple

VERSION = "HGH_PROVENANCE_V3"
HASH_NAME = "sha256"

def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canon(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = "\n".join(line.rstrip() for line in s.split("\n"))
    return unicodedata.normalize("NFC", s.strip())

def rfc6962_leaf(preimage: bytes) -> bytes:
    return H(b"\x00" + preimage)

def rfc6962_node(left: bytes, right: bytes) -> bytes:
    return H(b"\x01" + left + right)

def leaf_preimage(label: str, index: int, text: str, salt: bytes) -> bytes:
    return (
        VERSION.encode("utf-8") + b"\x00" +
        str(index).encode("utf-8") + b"\x00" +
        label.encode("utf-8") + b"\x00" +
        salt + b"\x00" +
        canon(text).encode("utf-8")
    )

def merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        raise ValueError("Cannot compute Merkle root of empty list.")
    layer = leaves[:]
    while len(layer) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i+1] if i+1 < len(layer) else a
            nxt.append(rfc6962_node(a, b))
        layer = nxt
    return layer[0]

def merkle_proof(leaves: List[bytes], idx: int) -> List[Dict[str, str]]:
    if idx < 0 or idx >= len(leaves):
        raise IndexError("idx out of range")
    proof: List[Dict[str, str]] = []
    layer = leaves[:]
    i = idx
    while len(layer) > 1:
        if i % 2 == 0:
            sib = i + 1
            if sib >= len(layer):
                sib = i
            proof.append({"side": "R", "hash": layer[sib].hex()})
        else:
            sib = i - 1
            proof.append({"side": "L", "hash": layer[sib].hex()})
        nxt: List[bytes] = []
        for j in range(0, len(layer), 2):
            a = layer[j]
            b = layer[j+1] if j+1 < len(layer) else a
            nxt.append(rfc6962_node(a, b))
        layer = nxt
        i //= 2
    return proof

def verify_proof(leaf: bytes, proof: List[Dict[str, str]], root: bytes) -> bool:
    cur = leaf
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        if step["side"] == "L":
            cur = rfc6962_node(sib, cur)
        elif step["side"] == "R":
            cur = rfc6962_node(cur, sib)
        else:
            raise ValueError("bad side")
    return cur == root

def manifest_hash(labels: List[str]) -> str:
    manifest = {"version": VERSION, "labels": labels}
    blob = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()

def load_derivations(path: str) -> Dict[str, str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("DERIVATIONS json must be an object {label: text}")
    return {str(k): str(v) for k, v in data.items()}

def main():
    ap = argparse.ArgumentParser(description="HGH provenance commit (RFC6962 Merkle + salts + proofs)")
    ap.add_argument("--derivations", required=True, help="Path to derivations JSON {label: text}")
    ap.add_argument("--outdir", default="out_provenance", help="Output directory")
    ap.add_argument("--hmac-key-hex", default="", help="Optional 32+ byte hex key for authorship tags (keep private)")
    args = ap.parse_args()

    derivs = load_derivations(args.derivations)
    labels = list(derivs.keys())

    os.makedirs(args.outdir, exist_ok=True)
    proofs_dir = os.path.join(args.outdir, "proofs")
    os.makedirs(proofs_dir, exist_ok=True)

    salts: List[bytes] = []
    leaves: List[bytes] = []
    preimages: List[bytes] = []

    for index1, label in enumerate(labels, start=1):
        salt = os.urandom(32)
        pre = leaf_preimage(label, index1, derivs[label], salt)
        leaf = rfc6962_leaf(pre)
        salts.append(salt)
        preimages.append(pre)
        leaves.append(leaf)

    root = merkle_root(leaves)
    mh = manifest_hash(labels)

    hmac_key = bytes.fromhex(args.hmac_key_hex) if args.hmac_key_hex else None
    tags_hex: List[str] = []
    if hmac_key is not None:
        for leaf in leaves:
            tags_hex.append(hmac.new(hmac_key, leaf, hashlib.sha256).hexdigest())

    for i, label in enumerate(labels):
        proof = merkle_proof(leaves, i)
        ok = verify_proof(leaves[i], proof, root)
        if not ok:
            raise RuntimeError(f"Proof generation failed for {label}")
        with open(os.path.join(proofs_dir, f"slot_{i+1:02d}.proof.json"), "w", encoding="utf-8") as f:
            json.dump({
                "version": VERSION,
                "slot_index": i+1,
                "label": label,
                "leaf": leaves[i].hex(),
                "root": root.hex(),
                "proof": proof,
                "hash": HASH_NAME,
                "manifest_hash": mh
            }, f, indent=2)

    public = {
        "version": VERSION,
        "hash": HASH_NAME,
        "manifest_hash": mh,
        "leaves": [{"slot": i+1, "label": label, "leaf": leaves[i].hex()} for i, label in enumerate(labels)],
        "merkle_root": root.hex(),
        "note": "To verify a slot later: reveal (label, slot_index, salt_hex, derivation_text). Recompute leaf+proof to root."
    }
    if tags_hex:
        public["authorship_tags_hmac_sha256_over_leaf_hex"] = [
            {"slot": i+1, "tag": tags_hex[i]} for i in range(len(tags_hex))
        ]

    with open(os.path.join(args.outdir, "public_commit.json"), "w", encoding="utf-8") as f:
        json.dump(public, f, indent=2)

    private = {
        "version": VERSION,
        "hash": HASH_NAME,
        "manifest_hash": mh,
        "merkle_root": root.hex(),
        "hmac_key_hex": (args.hmac_key_hex if args.hmac_key_hex else ""),
        "slots": []
    }
    for i, label in enumerate(labels):
        private["slots"].append({
            "slot": i+1,
            "label": label,
            "salt_hex": salts[i].hex(),
            "derivation_text_canonicalized": canon(derivs[label]),
            "leaf_hex": leaves[i].hex()
        })

    with open(os.path.join(args.outdir, "private_bundle.json"), "w", encoding="utf-8") as f:
        json.dump(private, f, indent=2)

    print("✅ Done.")
    print(f"Output dir: {args.outdir}")
    print(f"PUBLIC : {os.path.join(args.outdir, 'public_commit.json')}")
    print(f"PRIVATE: {os.path.join(args.outdir, 'private_bundle.json')}  (KEEP OFFLINE)")
    print(f"ROOT   : {root.hex()}")
    print(f"MANIFEST_HASH: {mh}")
    print(f"PROOFS : {proofs_dir}/slot_XX.proof.json")

if __name__ == "__main__":
    main()
