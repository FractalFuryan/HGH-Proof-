import sys
import json, hashlib

def H(b): return hashlib.sha256(b).digest()
def node(l, r): return H(b"\x01" + l + r)

def verify(leaf_hex, proof, root_hex):
    cur = bytes.fromhex(leaf_hex)
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        cur = node(sib, cur) if step["side"] == "L" else node(cur, sib)
    return cur.hex() == root_hex

if __name__ == "__main__":
    proof_file = sys.argv[1] if len(sys.argv) > 1 else "proofs/slot_01.proof.json"
    with open(proof_file) as f:
        p = json.load(f)
    ok = verify(p["leaf"], p["proof"], p["root"])
    print("VALID" if ok else "INVALID")
    sys.exit(0 if ok else 1)
