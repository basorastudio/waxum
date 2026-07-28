//! Contract test for the auth gate. Every route under `/api/v1/*` must
//! reject a missing or wrong bearer token; the four probe endpoints
//! (`/livez`, `/readyz`, `/health`, `/metrics`) must not.
mod common;

use axum::http::{Method, StatusCode};
use common::{call, req_get, req_json, Harness, TEST_TOKEN};
use serde_json::json;
use waxum::middleware::jwt::JwtAuth;

/// Matches the `JWT_SECRET` the harness sets so a test can mint its own
/// tokens with `JwtAuth::with_secret` and have them validate against the
/// app under test.
const TEST_JWT_SECRET: &str = "test-jwt-secret-value";

async fn create_session(h: &Harness, id: &str) {
    let (status, _) = call(
        &h.app,
        req_json(
            Method::POST,
            "/api/v1/sessions",
            Some(TEST_TOKEN),
            json!({"id": id}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session {id} setup failed");
}

#[tokio::test]
async fn api_v1_rejects_missing_token() {
    let h = Harness::new().await;
    let (status, _) = call(&h.app, req_get("/api/v1/sessions", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_v1_rejects_wrong_token() {
    let h = Harness::new().await;
    let (status, _) = call(&h.app, req_get("/api/v1/sessions", Some("nope"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_v1_accepts_superadmin_token() {
    let h = Harness::new().await;
    let (status, _) = call(&h.app, req_get("/api/v1/sessions", Some(TEST_TOKEN))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn probes_bypass_auth() {
    let h = Harness::new().await;
    for path in ["/livez", "/readyz", "/health", "/metrics"] {
        let (status, _) = call(&h.app, req_get(path, None)).await;
        assert_eq!(status, StatusCode::OK, "{} should bypass auth", path);
    }
}

#[tokio::test]
async fn issue_session_token_endpoint_returns_a_working_scoped_token() {
    let h = Harness::new().await;
    create_session(&h, "s-scope-a").await;

    let (status, body) = call(
        &h.app,
        req_json(
            Method::POST,
            "/api/v1/sessions/s-scope-a/token",
            Some(TEST_TOKEN),
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("session_id").and_then(|v| v.as_str()),
        Some("s-scope-a")
    );
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .expect("token field");

    let (status, _) = call(&h.app, req_get("/api/v1/sessions/s-scope-a", Some(token))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn scoped_token_cannot_reach_a_different_session() {
    let h = Harness::new().await;
    create_session(&h, "s-scope-mine").await;
    create_session(&h, "s-scope-other").await;

    let jwt = JwtAuth::with_secret(TEST_JWT_SECRET.to_string());
    let token = jwt
        .generate_token("s-scope-mine", "superadmin", 1, Some("s-scope-mine"))
        .expect("generate scoped token");

    let (status, _) = call(
        &h.app,
        req_get("/api/v1/sessions/s-scope-mine", Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "own session must stay reachable");

    let (status, _) = call(
        &h.app,
        req_get("/api/v1/sessions/s-scope-other", Some(&token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token scoped to one session must not reach another"
    );
}

#[tokio::test]
async fn scoped_token_cannot_reach_fleet_wide_endpoints() {
    let h = Harness::new().await;
    create_session(&h, "s-scope-fleet").await;

    let jwt = JwtAuth::with_secret(TEST_JWT_SECRET.to_string());
    let token = jwt
        .generate_token("s-scope-fleet", "superadmin", 1, Some("s-scope-fleet"))
        .expect("generate scoped token");

    for path in ["/api/v1/sessions", "/api/v1/sessions/search"] {
        let (status, _) = call(&h.app, req_get(path, Some(&token))).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{path} is fleet-wide and must reject a session-scoped token"
        );
    }
}

#[tokio::test]
async fn unscoped_jwt_still_reaches_every_session() {
    let h = Harness::new().await;
    create_session(&h, "s-scope-unrestricted").await;

    let jwt = JwtAuth::with_secret(TEST_JWT_SECRET.to_string());
    let token = jwt
        .generate_token("boot", "superadmin", 1, None)
        .expect("generate unscoped token");

    let (status, _) = call(
        &h.app,
        req_get("/api/v1/sessions/s-scope-unrestricted", Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(&h.app, req_get("/api/v1/sessions", Some(&token))).await;
    assert_eq!(status, StatusCode::OK);
}
