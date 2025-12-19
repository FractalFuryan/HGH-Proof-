# Makefile for HGH Provenance receipts

DERIVATIONS=derivations/derivations.json
OUTDIR=.
PYTHON=python3

all: receipts

receipts:
	$(PYTHON) src/hgh_provenance_v3.py --derivations $(DERIVATIONS) --outdir $(OUTDIR)

verify:
	$(PYTHON) src/verify_proof.py

.PHONY: all receipts verify
