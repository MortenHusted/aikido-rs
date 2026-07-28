.PHONY: build release install sign check gates clean

# ---------------------------------------------------------------------------
# Code signing — this is what stops macOS asking for keychain approval on
# every single rebuild.
#
# An ad-hoc (default) Rust binary has a designated requirement of
# `cdhash H"…"` — literally its own content hash — so every rebuild is a
# different program as far as the keychain is concerned, and "Always Allow"
# never survives. Signing with a stable identity changes the requirement to
# `identifier "…" and certificate leaf = H"…"`, which does survive:
#
#   ad-hoc:  designated => cdhash H"8307b359…"
#   signed:  designated => identifier "dev.aikido.cli" and certificate leaf = H"fd72dbe0…"
#
# The identity is a self-signed Code Signing certificate created once in
# Keychain Access (Certificate Assistant → Create a Certificate, Self Signed
# Root, type Code Signing). It reports CSSMERR_TP_NOT_TRUSTED because nothing
# vouches for it — that only affects verification, not signing, and the
# keychain ACL only needs the requirement to be stable.
#
# IDENTIFIER is set explicitly so it does not vary with the output filename;
# that way the built binary and the installed copy share one requirement and
# one approval covers both.
# ---------------------------------------------------------------------------
SIGN_IDENTITY ?= aikido-dev
IDENTIFIER    ?= dev.aikido.cli
BINDIR        ?= $(HOME)/.local/bin

build:
	cargo build --workspace
	@$(MAKE) --no-print-directory sign BIN=target/debug/aikido

release:
	cargo build --release -p aikido-cli
	@$(MAKE) --no-print-directory sign BIN=target/release/aikido

# Signs $(BIN) if the identity exists. A missing identity is a warning, not a
# failure: the build is still usable, it will just prompt for keychain access
# once per rebuild.
sign:
	@if [ -z "$(BIN)" ]; then echo "sign: pass BIN=<path>"; exit 1; fi
	@if [ ! -f "$(BIN)" ]; then echo "sign: $(BIN) does not exist"; exit 1; fi
	@if security find-identity -p codesigning 2>/dev/null | grep -q '"$(SIGN_IDENTITY)"'; then \
		codesign -s "$(SIGN_IDENTITY)" -i "$(IDENTIFIER)" --force "$(BIN)" 2>&1 | sed 's/^/  /'; \
		echo "  signed $(BIN) as $(IDENTIFIER)"; \
	else \
		echo "  WARNING: no '$(SIGN_IDENTITY)' code-signing identity found — leaving $(BIN) ad-hoc signed."; \
		echo "  Every rebuild will then need one keychain approval. See the signing note in this Makefile."; \
	fi

install: release
	cargo install --path crates/aikido-cli --root "$(shell dirname $(BINDIR))" --force
	@$(MAKE) --no-print-directory sign BIN=$(BINDIR)/aikido

# The same four gates CI-equivalent work is judged by.
gates: check
check:
	cargo build --workspace
	cargo test --workspace
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --check

clean:
	cargo clean
