# Hopae make targets. Names are fixed by docs/PROCESS.md (Make targets).
#
# Targets that need the Rust crate skip with a message while Cargo.toml is
# absent (milestone M0) and run for real, failing on error, once it exists.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

PYTHON ?= python3
CARGO_PRESENT := $(wildcard Cargo.toml)
ENV_FILE ?= $(HOME)/env
STATIC_TARGET ?= x86_64-unknown-linux-musl
DIST ?= dist

# $(call need-cargo,<description>) expands to a skip message or nothing.
ifeq ($(CARGO_PRESENT),)
define rust
	@echo "skip: $(1): no Cargo.toml yet (crate not created; this target fails once it exists)"
endef
else
define rust
	$(2)
endef
endif

.PHONY: test-postgres check check-boundary test audit check-docs scenario-coverage gates e2e coverage static release-assets tools-test

check: check-boundary
	$(call rust,check,cargo fmt --all -- --check && cargo clippy --all-targets --locked -- -D warnings)

# ADR-0013: gateway wire names stay inside src/gateway/. Needs no crate.
check-boundary:
	@$(PYTHON) tools/check_boundary.py

test:
	$(call rust,test,cargo test --locked --all-targets)

# ADR-0020: the store conformance suite against an ephemeral PostgreSQL
# container (tmpfs data, removed on exit). Needs Docker and the image.
test-postgres:
	tools/test_postgres.sh

audit:
	$(call rust,audit,cargo audit)

# Reads the Git index: stage the intended changes first. The denylist path
# comes from HOPAE_PUBLISH_DENYLIST (outside the repository); the env file's
# values are scanned for when it exists. Neither is ever printed.
check-docs:
	@$(PYTHON) tools/check_docs.py $(if $(wildcard $(ENV_FILE)),--env-file $(ENV_FILE),)

scenario-coverage:
	@$(PYTHON) tools/check_docs.py scenario-coverage

gates: check test audit check-docs scenario-coverage

e2e:
ifeq ($(wildcard tests/scenarios.rs),)
	@echo "skip: e2e: no tests/scenarios.rs yet (gateway-layer scenarios arrive with M1)"
else
	@test -n "$${HOPAE_E2E_GATEWAY_BINARY:-}" || { echo "e2e: HOPAE_E2E_GATEWAY_BINARY must name the gateway binary" >&2; exit 1; }
	cargo test --locked --test scenarios -- --ignored gateway
endif

coverage:
	$(call rust,coverage,cargo llvm-cov --locked --all-targets)

static:
	$(call rust,static,cargo build --release --locked --target $(STATIC_TARGET))

release-assets:
ifeq ($(CARGO_PRESENT),)
	@echo "skip: release-assets: no Cargo.toml yet"
else
	$(MAKE) static
	rm -rf $(DIST) && mkdir -p $(DIST)
	ver="$$(cargo pkgid | sed 's/.*[#@]//')"; \
	name="hopae-$$ver-$(STATIC_TARGET)"; \
	mkdir -p "$(DIST)/$$name" && \
	cp "target/$(STATIC_TARGET)/release/hopae" LICENSE README.md "$(DIST)/$$name/" && \
	tar -C $(DIST) -czf "$(DIST)/$$name.tar.gz" "$$name" && rm -rf "$(DIST)/$$name"; \
	cd $(DIST) && sha256sum *.tar.gz > SHA256SUMS
	@echo "release-assets: $(DIST)/SHA256SUMS written; signing is a separate step (docs/PROCESS.md)"
endif

# Unit tests for the tooling itself (not part of gates).
tools-test:
	$(PYTHON) -m unittest tools/test_check_docs.py
