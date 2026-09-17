.PHONY: build release install sign check gates audit cross-check clean

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
# vouches for it — that only affects verification, not signing.
#
# HOW MUCH THIS HELPS IS NOT ESTABLISHED. Three rebuilds straight after an
# approval ran clean, but a later rebuild prompted again, so that run was
# probably measuring a short-lived authorisation cache rather than the
# requirement actually matching. A stable requirement is still strictly better
# than a content hash and costs nothing — but treat the prompt as reduced, not
# eliminated, until someone measures it over a longer window.
#
# For anything unattended, do not depend on this at all. Set
# AIKIDO_TOKEN_STORE=file to take the keychain out of the path entirely; a
# scheduled job must never be one dialog away from doing nothing.
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

# The five gates CI judges by. The audit runs last so a stale advisory
# database never masks a compile or test failure; it fails the build on any
# known vulnerability in Cargo.lock because this binary holds API credentials.
gates: check
check:
	cargo build --workspace
	cargo test --workspace
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --check
	@$(MAKE) --no-print-directory audit

audit:
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "audit: cargo-audit not installed (cargo install cargo-audit) — skipping locally; CI enforces it"; \
	fi

# Type-check the Linux and Windows targets from this machine. The credential
# store is cfg-gated per platform, so a Mac-only build can be green while the
# Linux or Windows binary does not compile; this catches that before CI does.
# ring compiles C for the target, so a plain `cargo check --target` fails on
# a Mac for want of a musl or MinGW C compiler; cargo-zigbuild supplies one
# through zig for every target here. Windows is checked as the GNU target
# because zig cannot stand in for MSVC; the release matrix builds MSVC on a
# native Windows runner and CI runs the full suite there. One-time setup:
#   brew install zig && cargo install cargo-zigbuild
#   rustup target add $(CROSS_TARGETS)
CROSS_TARGETS ?= x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu
cross-check:
	@command -v cargo-zigbuild >/dev/null 2>&1 || { echo "cross-check: needs cargo-zigbuild and zig (see Makefile)"; exit 1; }
	@for target in $(CROSS_TARGETS); do \
		echo "== cargo-zigbuild clippy --target $$target"; \
		cargo-zigbuild clippy --workspace --all-targets --locked --target $$target -- -D warnings || exit 1; \
	done

clean:
	cargo clean
