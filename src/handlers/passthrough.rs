//! Catch-all fallback handler.
//!
//! Forwards any request whose path is not handled by an explicit route to
//! upstream Ollama as a raw HTTP passthrough. The proxy applies **no**
//! security scanning to these requests; they exist so transparent
//! compatibility with future Ollama API additions and the OpenAI / Anthropic
//! compatibility shims (`/v1/chat/completions`, `/v1/messages`, `/v1/embeddings`,
//! …) is not gated on this proxy adding explicit support.
//!
//! ## Security note for operators
//!
//! Anything that flows through this fallback is **not scanned by PANW AIRS**.
//! When you onboard a new Ollama endpoint where prompt or response content
//! must be assessed, add an explicit handler that calls
//! `state.security_client.assess_content(...)` before forwarding.
//!
//! The fallback can be disabled at runtime by setting
//! `PASSTHROUGH_DISABLED=1`, in which case unhandled paths return `404`.

use axum::{
    body::Body,
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, Response, StatusCode},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use tracing::{info, warn};

use crate::AppState;

/// Returns true when the operator has explicitly opted out of passthrough.
fn passthrough_disabled() -> bool {
    matches!(
        std::env::var("PASSTHROUGH_DISABLED").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Strips per-hop response headers that must not be forwarded as-is.
fn sanitize_response_headers(src: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut dst = HeaderMap::new();
    for (name, value) in src.iter() {
        let n = name.as_str().to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "connection"
                | "transfer-encoding"
                | "content-length"
                | "upgrade"
                | "proxy-connection"
                | "keep-alive"
        ) {
            continue;
        }
        if let Ok(name) = axum::http::HeaderName::try_from(name.as_str()) {
            if let Ok(value) = axum::http::HeaderValue::try_from(value.as_bytes()) {
                dst.append(name, value);
            }
        }
    }
    dst
}

/// Catch-all fallback handler. Mounted via `Router::fallback`.
pub async fn passthrough(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    if passthrough_disabled() {
        warn!(
            "Passthrough disabled (PASSTHROUGH_DISABLED=1); rejecting {} {}",
            method, uri
        );
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .expect("build 404 response");
    }

    info!(
        "Passthrough (no scan) {} {} -> upstream Ollama",
        method, uri
    );

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());

    // Collect the request body up to the configured cap. Streaming uploads
    // (e.g. /api/blobs/:digest with a large GGUF) are bounded by the host's
    // `Body` limits already; no extra copy here beyond what axum buffers.
    let body_bytes: Bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            warn!("Failed to read passthrough request body: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Failed to read request body"))
                .expect("build 400 response");
        }
    };

    // Convert axum HeaderMap into reqwest HeaderMap.
    let mut upstream_headers = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        if let Ok(n) = reqwest::header::HeaderName::try_from(name.as_str()) {
            if let Ok(v) = reqwest::header::HeaderValue::try_from(value.as_bytes()) {
                upstream_headers.append(n, v);
            }
        }
    }

    // Convert axum Method to reqwest Method via byte string.
    let upstream_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Method Not Allowed"))
                .expect("build 405 response");
        }
    };

    let upstream = match state
        .ollama_client
        .forward_raw(upstream_method, &path_and_query, upstream_headers, body_bytes)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Passthrough upstream error: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Upstream Ollama unavailable."))
                .expect("build 502 response");
        }
    };

    let status = match StatusCode::from_u16(upstream.status().as_u16()) {
        Ok(s) => s,
        Err(_) => StatusCode::BAD_GATEWAY,
    };
    let resp_headers = sanitize_response_headers(upstream.headers());

    // Stream the upstream body back to the client without buffering. This
    // matters for /v1/chat/completions SSE streams and large /api/blobs
    // downloads.
    let stream = upstream.bytes_stream();
    let body = Body::from_stream(stream);

    let mut builder = Response::builder().status(status);
    if let Some(h) = builder.headers_mut() {
        *h = resp_headers;
    }
    builder.body(body).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from("Failed to construct upstream response"))
            .expect("build 502 fallback")
    })
}
