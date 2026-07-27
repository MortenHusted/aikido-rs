//! Keychain interop with the Go CLI (zalando/go-keyring).
//!
//! go-keyring's macOS backend stores every value as
//! `go-keyring-base64:` + base64(payload) via the `security` CLI. The first
//! Rust build parsed the raw keychain value as JSON, so every entry written
//! by the Go CLI read back as garbage and the user appeared logged out.
//! These tests pin the codec (all platforms) and, on macOS, prove both
//! directions end to end against the real login keychain using a throwaway
//! service name — never the real `aikido-cli` entry.

use aikido_core::credentials::{decode_go_keyring_payload, encode_go_keyring_payload, Credentials};

const SAMPLE_JSON: &str = r#"{"client_id":"id-1","client_secret":"sec-1","access_token":"tok-1","expires_at":"2030-01-01T00:00:00Z"}"#;

// ---------------------------------------------------------------------------
// Codec (runs everywhere)
// ---------------------------------------------------------------------------

#[test]
fn encode_matches_go_keyring_wire_format() {
    // base64("hello") == "aGVsbG8=" — the exact string go-keyring writes.
    assert_eq!(
        encode_go_keyring_payload("hello"),
        "go-keyring-base64:aGVsbG8="
    );
}

#[test]
fn decode_round_trips_the_encoder() {
    let encoded = encode_go_keyring_payload(SAMPLE_JSON);
    assert_eq!(decode_go_keyring_payload(&encoded).unwrap(), SAMPLE_JSON);
}

#[test]
fn decode_accepts_legacy_hex_prefix() {
    // hex("hi") == "6869"
    assert_eq!(
        decode_go_keyring_payload("go-keyring-encoded:6869").unwrap(),
        "hi"
    );
}

#[test]
fn decode_passes_raw_values_through() {
    // Entries written without a prefix (e.g. by other tools) stay readable,
    // matching go-keyring's own reader.
    assert_eq!(decode_go_keyring_payload(SAMPLE_JSON).unwrap(), SAMPLE_JSON);
    // go-keyring trims whitespace from `security` output; so do we.
    assert_eq!(decode_go_keyring_payload("raw\n").unwrap(), "raw");
}

#[test]
fn decode_rejects_corrupt_base64() {
    assert!(decode_go_keyring_payload("go-keyring-base64:!!!not-base64!!!").is_err());
}

// ---------------------------------------------------------------------------
// End-to-end against the macOS login keychain (throwaway service)
// ---------------------------------------------------------------------------
//
// These two tests are `#[ignore]` and run only via
// `cargo test -p aikido-core --test keychain_interop -- --ignored`.
// They touch the real login keychain (throwaway service names, never the
// real `aikido-cli` entry), and macOS pops a modal ACL prompt when the
// freshly-built test binary reads an item another process wrote — the test
// binary's signature changes on every rebuild, so the prompt cannot be
// pre-approved. A default `cargo test` must never block on a human, so the
// keychain round-trip is the one code path a default run does not cover;
// the go-keyring payload codec above carries the regression value.

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use aikido_core::credentials::CredentialStore;
    use std::process::Command;

    /// Skip (returning false) when no usable keychain is available — CI
    /// runners without a login keychain must not fail these tests.
    fn keychain_available() -> bool {
        let usable = Command::new("/usr/bin/security")
            .arg("default-keychain")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !usable {
            eprintln!("skipping keychain interop test: no default keychain available");
        }
        usable
    }

    fn security_delete(service: &str) {
        let _ = Command::new("/usr/bin/security")
            .args(["delete-generic-password", "-s", service, "-a", "default"])
            .output();
    }

    /// Go → Rust: an entry written exactly the way go-keyring writes it
    /// (security CLI, go-keyring-base64 payload) must load through
    /// CredentialStore. `-A` keeps the throwaway item prompt-free; the
    /// payload encoding under test is identical either way.
    #[test]
    #[ignore = "touches the login keychain and can trigger a modal ACL prompt; run with -- --ignored"]
    fn entry_written_like_go_keyring_loads_through_the_store() {
        if !keychain_available() {
            return;
        }
        let service = format!("aikido-cli-interop-check-go2rs-{}", std::process::id());
        security_delete(&service);

        let payload = encode_go_keyring_payload(SAMPLE_JSON);
        let status = Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-U",
                "-A",
                "-s",
                &service,
                "-a",
                "default",
                "-w",
                &payload,
            ])
            .status()
            .expect("running security CLI");
        assert!(status.success(), "security add-generic-password failed");

        let store = CredentialStore::keychain_at_service(&service);
        let loaded = store.load().expect("load").expect("entry present");
        security_delete(&service);

        assert_eq!(loaded.client_id, "id-1");
        assert_eq!(loaded.client_secret, "sec-1");
        assert_eq!(loaded.access_token, "tok-1");
        assert_eq!(loaded.expires_at, "2030-01-01T00:00:00Z");
    }

    /// Rust → Go: an entry saved through CredentialStore must read back via
    /// the security CLI (go-keyring's read path) as the go-keyring-base64
    /// format, decoding to the exact JSON the Go CLI expects.
    #[test]
    #[ignore = "touches the login keychain and can trigger a modal ACL prompt; run with -- --ignored"]
    fn store_written_entry_is_readable_the_way_go_keyring_reads() {
        if !keychain_available() {
            return;
        }
        let service = format!("aikido-cli-interop-check-rs2go-{}", std::process::id());
        security_delete(&service);

        let store = CredentialStore::keychain_at_service(&service);
        store
            .save(&Credentials {
                client_id: "id-2".into(),
                client_secret: "sec-2".into(),
                access_token: "tok-2".into(),
                expires_at: "2031-01-01T00:00:00Z".into(),
            })
            .expect("save");

        // Read exactly like go-keyring's Get: `security find-generic-password
        // -s <service> -wa default`, then strip/decode the prefix.
        let output = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", &service, "-wa", "default"])
            .output()
            .expect("running security CLI");
        store.clear().expect("clear");
        security_delete(&service);

        assert!(
            output.status.success(),
            "security find-generic-password failed"
        );
        let raw = String::from_utf8(output.stdout).expect("utf-8 security output");
        assert!(
            raw.trim().starts_with("go-keyring-base64:"),
            "store must write the go-keyring wire format, got a different prefix"
        );
        let json = decode_go_keyring_payload(&raw).expect("decode like go-keyring");
        let creds: Credentials = serde_json::from_str(&json).expect("Go-parseable JSON");
        assert_eq!(creds.client_id, "id-2");
        assert_eq!(creds.client_secret, "sec-2");
        assert_eq!(creds.access_token, "tok-2");
    }
}
