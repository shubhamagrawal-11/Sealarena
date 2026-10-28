.PHONY: demo demo-native leaktest verify tamper clean docker-up docker-down help

PYTHON := python

help:
	@echo "SealArena: Secure Multi-Tenant Evaluation Sandbox"
	@echo "=================================================="
	@echo "make demo         - Start SealArena demo (auto-detects Docker or native)"
	@echo "make demo-native  - Force start native microservices runtime"
	@echo "make leaktest     - Run automated 9-vector leak-test suite"
	@echo "make verify       - Verify Ed25519 hash-chained forensic audit ledger"
	@echo "make tamper       - Run interactive audit ledger tamper demonstration"
	@echo "make docker-up    - Build and launch all 7 microservices via Docker Compose"
	@echo "make docker-down  - Stop and remove Docker Compose containers"
	@echo "make clean        - Clean temporary logs, cache files, and test state"

demo:
	$(PYTHON) demo.py

demo-native:
	$(PYTHON) demo.py --native

leaktest:
	$(PYTHON) demo.py --leaktest

verify:
	$(PYTHON) demo.py --verify

tamper:
	$(PYTHON) demo.py --tamper

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	@echo "Cleaning up..."
	rm -rf data/audit_ledger.jsonl data/leaktest_results.json configs/encrypted_blue_rules.bin certs/*.key certs/*.crt
