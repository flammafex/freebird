// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use futures_util::future::BoxFuture;
use std::task::{Context, Poll};
use tower::Layer;

/// Tower layer that enforces TLS when the `REQUIRE_TLS` environment variable
/// is set to `"true"`.
///
/// When active, requests must either:
/// - Use an `https` URI scheme, **or**
/// - Carry an `X-Forwarded-Proto: https` header (for reverse-proxy deployments).
///
/// Non-compliant requests are rejected with HTTP 400.
#[derive(Clone)]
pub struct TlsEnforcementLayer {
    require_tls: bool,
}

impl TlsEnforcementLayer {
    pub fn new() -> Self {
        let require_tls = std::env::var("REQUIRE_TLS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        Self { require_tls }
    }
}

impl Default for TlsEnforcementLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for TlsEnforcementLayer {
    type Service = TlsEnforcementService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsEnforcementService {
            inner,
            require_tls: self.require_tls,
        }
    }
}

#[derive(Clone)]
pub struct TlsEnforcementService<S> {
    inner: S,
    require_tls: bool,
}

impl<S> tower::Service<Request<Body>> for TlsEnforcementService<S>
where
    S: tower::Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if self.require_tls {
            let scheme_https = req.uri().scheme() == Some(&axum::http::uri::Scheme::HTTPS);
            let forwarded_https = req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("https"))
                .unwrap_or(false);

            if !scheme_https && !forwarded_https {
                let response = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"error": "tls_required", "message": "HTTPS is required"}"#,
                    ))
                    .unwrap();
                return Box::pin(async move { Ok(response) });
            }
        }

        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move { inner.call(req).await })
    }
}
