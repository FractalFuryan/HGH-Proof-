# HGH Provenance

This repository provides a cryptographically verifiable provenance system
for mathematical derivations used in the HGH / FHCM project.

The goal is simple:

> Prove that specific derivations existed at a specific time,
> without revealing their contents publicly.

This prevents misattribution, plagiarism claims, or authorship disputes.

---

## What is published

- A Merkle commitment over all derivations
- Individual salted leaf hashes
- Inclusion proofs for selective verification

No derivation text or salts are public.

---

## Cryptographic design

- Canonical text normalization
- SHA-256 hashing
- RFC6962-style Merkle tree
- 32-byte per-slot random salts
- Optional HMAC authorship binding (private)
- Deterministic verification

This is standard, boring cryptography by design.

---

## How verification works

To verify a revealed derivation:

1. Take:
   - derivation text
   - its salt
   - its slot index + label
   - the published proof file
2. Recompute the leaf hash
3. Walk the Merkle proof
4. Confirm it matches the published Merkle root

No trust required.

---

## Automation

### One-command generation

Use the Makefile for easy generation:

```bash
make receipts
```

To verify a proof (default: slot 01):

```bash
make verify
```

Or verify a specific proof:

```bash
python3 src/verify_proof.py proofs/slot_02.proof.json
```

### Continuous Integration (CI)

Every push or pull request that changes proofs or the commit will automatically verify all proofs using GitHub Actions.

---

## What this does NOT claim

- This does not assert novelty.
- This does not assert correctness.
- This does not prevent independent rediscovery.

It proves *existence and authorship timeline only*.

---

## License

MIT — this system is intended to be reusable.
