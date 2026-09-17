//! `aikido api get` — read-only raw passthrough to the Aikido public API.
//!
//! An escape hatch for routes the CLI has no dedicated command for (e.g.
//! `/openapi/spec`). Read-only by design: no mutation passthrough exists,
//! because a generic write would sit outside the audited command surface
//! and this CLI feeds an unattended security loop.

use aikido_core::error::ApiError;

use crate::output::{render_ok, GlobalFlags, Response};

use super::issues::render_failure;
use super::require_session;

pub async fn get(flags: &GlobalFlags, path: &str, query: &[String]) -> Result<(), ApiError> {
    let path = validate_path(path)?;
    let query = parse_query(query)?;
    let query_pairs: Vec<(&str, String)> = query
        .iter()
        .map(|(key, value)| (key.as_str(), value.clone()))
        .collect();

    let session = require_session(flags)?;
    let data = session.client.get(&path, &query_pairs).await?;
    render_ok(&flags.format(), Response::new(data), &[], None).map_err(render_failure)
}

/// The path must stay inside the API base: relative (`/...`), no scheme or
/// host, no `..` traversal, no inline query/fragment (use `--query`).
///
/// Percent signs and backslashes are rejected outright: the URL parser
/// normalises `%2e%2e` to `..` and `\` to `/` before the request goes out,
/// so a textual `..` check alone let `/%2e%2e/%2e%2e/oauth/token` reach the
/// OAuth endpoint. Aikido's public routes are plain ASCII identifiers, so
/// neither character has a legitimate use here; anything that needs
/// encoding belongs in `--query`, which reqwest encodes itself.
fn validate_path(path: &str) -> Result<String, ApiError> {
    let invalid = |reason: &str| {
        Err(ApiError::Api {
            status: 400,
            message: format!("invalid path {path:?}: {reason}"),
        })
    };
    if !path.starts_with('/') {
        return invalid("must start with '/' (relative to the API base, e.g. /openapi/spec)");
    }
    if path.contains("://") || path.starts_with("//") {
        return invalid("must not carry a scheme or host");
    }
    if path.contains('%') || path.contains('\\') {
        return invalid("must not contain '%' or '\\' (they are normalised into traversal)");
    }
    if path.split('/').any(|segment| segment == "..") {
        return invalid("must not traverse outside the API base");
    }
    if path.contains('?') || path.contains('#') {
        return invalid("pass query parameters via --query k=v, not inline");
    }
    if path.chars().any(char::is_whitespace) {
        return invalid("must not contain whitespace");
    }
    Ok(path.to_string())
}

fn parse_query(query: &[String]) -> Result<Vec<(String, String)>, ApiError> {
    query
        .iter()
        .map(|pair| {
            pair.split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .ok_or_else(|| ApiError::Api {
                    status: 400,
                    message: format!("invalid --query {pair:?}: expected k=v"),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_relative_api_paths() {
        assert!(validate_path("/openapi/spec").is_ok());
        assert!(validate_path("/issues/export").is_ok());
    }

    #[test]
    fn rejects_paths_that_escape_the_base() {
        for bad in [
            "openapi/spec",               // not rooted
            "https://evil.example/x",     // absolute URL
            "//evil.example/x",           // protocol-relative
            "/issues/../../oauth/token",  // traversal
            "/%2e%2e/%2e%2e/oauth/token", // encoded traversal the URL parser would normalise
            "/issues\\..\\..\\oauth",     // backslashes the URL parser treats as '/'
            "/spec?x=1",                  // inline query
            "/spec#frag",                 // fragment
            "/spec with space",           // whitespace
        ] {
            assert!(validate_path(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn parses_query_pairs_and_rejects_malformed_ones() {
        let parsed = parse_query(&["a=1".into(), "b=two=three".into()]).unwrap();
        assert_eq!(
            parsed,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "two=three".to_string())
            ]
        );
        assert!(parse_query(&["novalue".into()]).is_err());
    }
}
