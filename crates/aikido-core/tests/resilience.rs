//! Timeout, retry, and strict-body behaviour. This client feeds an
//! unattended scheduled security loop: it must fail rather than hang, ride
//! out transient throttling, and never turn a garbage response into a
//! clean-looking empty result.

use std::time::Duration;

use aikido_core::api::{self, IssueFilters};
use aikido_core::client::Client;
use aikido_core::error::ApiError;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_hanging_response_times_out_instead_of_hanging_forever() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([]))
                .set_delay(Duration::from_secs(30)),
        )
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok").with_request_timeout(Duration::from_millis(200));
    let started = std::time::Instant::now();
    let err = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .expect_err("must time out");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "timed out too slowly: {:?}",
        started.elapsed()
    );
    match err {
        ApiError::Transport(inner) => assert!(inner.is_timeout(), "expected timeout: {inner}"),
        other => panic!("expected Transport(timeout), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 429 retry with Retry-After
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_retries_a_429_honouring_retry_after_and_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "id": 1 }])))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let issues = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap();
    assert_eq!(issues.len(), 1);
}

#[tokio::test]
async fn persistent_429_gives_up_after_bounded_retries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .expect(3) // initial + exactly 2 retries, never more
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let err = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "rate_limit");
}

/// A 429 rejects the request without processing it, so retrying a mutation
/// is safe — the replay is the first execution.
#[tokio::test]
async fn mutation_retries_429_and_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/7/ignore"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/7/ignore"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::ignore_issue(&client, 7, Some("dup")).await.unwrap();
}

/// A 502/504 is ambiguous — the origin may have processed the request — so
/// mutations must NOT be replayed. Exactly one attempt.
#[tokio::test]
async fn mutation_does_not_retry_ambiguous_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/issues/5/severity/adjust"))
        .respond_with(ResponseTemplate::new(502))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let err = api::adjust_severity(&client, 5, "low", "reason")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "api_error");
}

/// GETs are idempotent, so transient 5xx statuses are retried.
#[tokio::test]
async fn get_retries_a_transient_503() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    assert!(api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap()
        .is_empty());
}

// ---------------------------------------------------------------------------
// Strict 2xx bodies: garbage must never read as "no findings"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_2xx_body_is_an_error_not_a_clean_empty_result() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html>load balancer error page</html>"),
        )
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let err = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .expect_err("garbage body must be an error");
    assert_eq!(err.code(), "api_error");
    assert!(
        err.to_string().contains("not valid JSON"),
        "error must say the body was undecodable: {err}"
    );
}

/// The genuine empty case stays a success — an empty array is a real
/// all-clear, not a decoding accident.
#[tokio::test]
async fn a_legitimately_empty_issue_list_is_still_ok() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let issues = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap();
    assert!(issues.is_empty());
}
