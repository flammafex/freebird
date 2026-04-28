// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use futures_util::future::BoxFuture;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower::Layer;

/// Tower layer that provides simple IP-based rate limiting for public endpoints.
///
/// Defaults:
/// - Window: 1 second
/// - Max requests per window: 30
/// - Cleanup: entries older than 2 seconds are purged lazily on each request
#[derive(Clone)]
pub struct PublicRateLimitLayer {
    state: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
    cleanup_after: Duration,
}

impl PublicRateLimitLayer {
    pub fn new(max_requests: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(1),
            cleanup_after: Duration::from_secs(2),
        }
    }
}

impl Default for PublicRateLimitLayer {
    fn default() -> Self {
        Self::new(30)
    }
}

impl<S> Layer<S> for PublicRateLimitLayer {
    type Service = PublicRateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PublicRateLimitService {
            inner,
            state: Arc::clone(&self.state),
            max_requests: self.max_requests,
            window: self.window,
            cleanup_after: self.cleanup_after,
        }
    }
}

#[derive(Clone)]
pub struct PublicRateLimitService<S> {
    inner: S,
    state: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
    cleanup_after: Duration,
}

impl<S> tower::Service<Request<Body>> for PublicRateLimitService<S>
where
    S: tower::Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let ip = extract_ip(&req);

        let state = Arc::clone(&self.state);
        let max_requests = self.max_requests;
        let window = self.window;
        let cleanup_after = self.cleanup_after;

        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            let now = Instant::now();

            let allowed = {
                let mut map = state.lock().unwrap_or_else(|e| e.into_inner());

                map.retain(|_, timestamps| {
                    timestamps.retain(|t| now.duration_since(*t) < cleanup_after);
                    !timestamps.is_empty()
                });

                if let Some(ip) = ip {
                    let timestamps = map.entry(ip).or_default();
                    timestamps.retain(|t| now.duration_since(*t) < window);
                    if timestamps.len() >= max_requests {
                        false
                    } else {
                        timestamps.push(now);
                        true
                    }
                } else {
                    true
                }
            };

            if !allowed {
                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header(axum::http::header::RETRY_AFTER, "1")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"error":"rate_limited","message":"Too many requests. Retry after 1 second."}"#,
                    ))
                    .unwrap();
                return Ok(response);
            }

            inner.call(req).await
        })
    }
}

fn extract_ip(req: &Request<Body>) -> Option<IpAddr> {
    if let Some(connect_info) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return Some(connect_info.ip());
    }

    if let Some(header) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = header.to_str() {
            let first = s.split(',').next().map(str::trim).unwrap_or(s);
            if let Ok(addr) = first.parse::<std::net::IpAddr>() {
                return Some(addr);
            }
        }
    }

    None
}
