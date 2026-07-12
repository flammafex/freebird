// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, Response, StatusCode};
use futures_util::future::BoxFuture;
use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll};
use tower::Layer;

#[derive(Clone, Debug)]
pub struct TlsEnforcementLayer {
    require_tls: bool,
    behind_proxy: bool,
    trusted_proxy_cidrs: Vec<Network>,
}

/// Client address after the trusted-proxy boundary has been validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedClientIp(pub IpAddr);

#[derive(Clone, Copy, Debug)]
struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    fn contains(self, ip: IpAddr) -> bool {
        if self.address.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let (a, b, bits): (u128, u128, u32) = match (self.address, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                (u128::from(u32::from(a)), u128::from(u32::from(b)), 32)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128),
            _ => unreachable!(),
        };
        let mask = if self.prefix == 0 {
            0
        } else {
            !0u128 << (bits - u32::from(self.prefix))
        };
        (a & mask) == (b & mask)
    }
}

fn parse_cidrs(value: &str) -> Result<Vec<Network>, String> {
    if value.trim().is_empty() {
        return Err("TRUSTED_PROXY_CIDRS must not be empty".into());
    }
    value
        .split(',')
        .map(|item| {
            let (address, prefix) = item
                .trim()
                .split_once('/')
                .ok_or_else(|| "invalid TRUSTED_PROXY_CIDRS entry".to_string())?;
            let address: IpAddr = address
                .parse()
                .map_err(|_| "invalid TRUSTED_PROXY_CIDRS address".to_string())?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| "invalid TRUSTED_PROXY_CIDRS prefix".to_string())?;
            if prefix > if address.is_ipv4() { 32 } else { 128 } {
                return Err("invalid TRUSTED_PROXY_CIDRS prefix".into());
            }
            Ok(Network { address, prefix })
        })
        .collect()
}

/// Validates the exact CIDR grammar used by the runtime proxy boundary.
pub fn validate_trusted_proxy_cidrs(value: &str) -> Result<(), String> {
    parse_cidrs(value).map(|_| ())
}

impl TlsEnforcementLayer {
    pub fn from_env() -> Result<Self, String> {
        let require_tls = env_flag("REQUIRE_TLS");
        let behind_proxy = env_flag("BEHIND_PROXY");
        if require_tls && !behind_proxy {
            return Err("REQUIRE_TLS=true requires BEHIND_PROXY=true".into());
        }
        let trusted_proxy_cidrs = if behind_proxy {
            parse_cidrs(&std::env::var("TRUSTED_PROXY_CIDRS").map_err(|_| {
                "TRUSTED_PROXY_CIDRS is required when BEHIND_PROXY=true".to_string()
            })?)?
        } else {
            Vec::new()
        };
        Ok(Self {
            require_tls,
            behind_proxy,
            trusted_proxy_cidrs,
        })
    }

    pub fn new() -> Self {
        Self::from_env().expect("invalid trusted proxy configuration")
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

fn forwarded_ip(headers: &HeaderMap, peer: Option<IpAddr>, cidrs: &[Network]) -> Option<IpAddr> {
    let peer = peer?;
    if !cidrs.iter().copied().any(|n| n.contains(peer)) {
        return None;
    }
    let xfp: Vec<_> = headers.get_all("x-forwarded-proto").iter().collect();
    let xff: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
    if !(xfp.len() == 1
        && xff.len() == 1
        && xfp[0].to_str().ok() == Some("https")
        && xff[0]
            .to_str()
            .ok()
            .and_then(|v| {
                if v.contains(',') {
                    None
                } else {
                    v.trim().parse::<IpAddr>().ok()
                }
            })
            .is_some())
    {
        return None;
    }
    xff[0].to_str().ok()?.trim().parse().ok()
}

#[cfg(test)]
fn valid_forwarded(headers: &HeaderMap, peer: Option<IpAddr>, cidrs: &[Network]) -> bool {
    forwarded_ip(headers, peer, cidrs).is_some()
}

fn rejection_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"error":"bad_request"}"#))
        .expect("static rejection response is valid")
}

/// Returns only the already validated peer identity. Forwarded headers are
/// deliberately not parsed by identity consumers; the middleware handles
/// them once and rewrites `ConnectInfo`/inserts `ValidatedClientIp`.
pub fn validated_client_ip(peer: Option<IpAddr>) -> Option<IpAddr> {
    peer
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
            config: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct TlsEnforcementService<S> {
    inner: S,
    config: TlsEnforcementLayer,
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
    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        let scheme_https = req
            .uri()
            .scheme()
            .is_some_and(|s| s == &axum::http::uri::Scheme::HTTPS);
        let forwarded = if self.config.behind_proxy {
            forwarded_ip(req.headers(), peer, &self.config.trusted_proxy_cidrs)
        } else {
            peer
        };
        let accepted = forwarded.is_some();
        let tls_ok = scheme_https || (self.config.behind_proxy && accepted);
        if !accepted || (self.config.require_tls && !tls_ok) {
            tracing::warn!("rejected request at trusted-proxy/TLS boundary");
            return Box::pin(async { Ok(rejection_response()) });
        }
        let Some(client_ip) = forwarded else {
            return Box::pin(async { Ok(rejection_response()) });
        };
        req.extensions_mut().insert(ValidatedClientIp(client_ip));
        // Preserve readiness: call the same service instance whose readiness
        // was polled rather than dispatching through a fresh clone.
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);
        Box::pin(async move { inner.call(req).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    #[test]
    fn cidr_contains() {
        assert!(Network {
            address: "10.0.0.0".parse().unwrap(),
            prefix: 8
        }
        .contains("10.1.2.3".parse().unwrap()));
    }
    #[test]
    fn rejects_multiple_forwarded_values() {
        let mut h = HeaderMap::new();
        h.append("x-forwarded-proto", HeaderValue::from_static("https"));
        h.append("x-forwarded-proto", HeaderValue::from_static("https"));
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        assert!(!valid_forwarded(
            &h,
            Some("10.0.0.1".parse().unwrap()),
            &[Network {
                address: "10.0.0.0".parse().unwrap(),
                prefix: 8
            }]
        ));
    }

    #[test]
    fn accepts_only_a_trusted_peer_with_single_valid_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        let cidrs = [Network {
            address: "10.0.0.0".parse().unwrap(),
            prefix: 8,
        }];
        assert!(valid_forwarded(
            &headers,
            Some("10.0.0.7".parse().unwrap()),
            &cidrs
        ));
        assert!(!valid_forwarded(
            &headers,
            Some("192.0.2.9".parse().unwrap()),
            &cidrs
        ));
    }

    #[test]
    fn rejects_missing_malformed_and_comma_separated_values() {
        let cidrs = [Network {
            address: "10.0.0.0".parse().unwrap(),
            prefix: 8,
        }];
        for (proto, client) in [
            (None, "192.0.2.1"),
            (Some("http"), "192.0.2.1"),
            (Some("https"), "192.0.2.1, 198.51.100.1"),
            (Some("https"), "not-an-ip"),
        ] {
            let mut headers = HeaderMap::new();
            if let Some(proto) = proto {
                headers.insert("x-forwarded-proto", HeaderValue::from_static(proto));
            }
            headers.insert("x-forwarded-for", HeaderValue::from_str(client).unwrap());
            assert!(!valid_forwarded(
                &headers,
                Some("10.0.0.7".parse().unwrap()),
                &cidrs
            ));
        }
    }

    #[tokio::test]
    async fn middleware_preserves_peer_and_inserts_validated_client_ip() {
        use std::convert::Infallible;
        use std::future::Ready;
        use std::task::Poll;
        use tower::Service;

        #[derive(Clone)]
        struct Echo;
        impl Service<Request<Body>> for Echo {
            type Response = Response<Body>;
            type Error = Infallible;
            type Future = Ready<Result<Self::Response, Self::Error>>;
            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, request: Request<Body>) -> Self::Future {
                assert_eq!(
                    request
                        .extensions()
                        .get::<ConnectInfo<SocketAddr>>()
                        .unwrap()
                        .0
                        .ip(),
                    "10.0.0.7".parse::<IpAddr>().unwrap()
                );
                assert_eq!(
                    request.extensions().get::<ValidatedClientIp>().unwrap().0,
                    "192.0.2.1".parse::<IpAddr>().unwrap()
                );
                std::future::ready(Ok(Response::new(Body::empty())))
            }
        }

        let layer = TlsEnforcementLayer {
            require_tls: true,
            behind_proxy: true,
            trusted_proxy_cidrs: parse_cidrs("10.0.0.0/8").unwrap(),
        };
        let mut service = layer.layer(Echo);
        let mut request = Request::new(Body::empty());
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((
                "10.0.0.7".parse::<std::net::IpAddr>().unwrap(),
                1234,
            ))));
        request
            .headers_mut()
            .insert("x-forwarded-proto", HeaderValue::from_static("https"));
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static(" 192.0.2.1 "));
        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut spoofed = Request::new(Body::empty());
        spoofed
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((
                "198.51.100.9".parse::<std::net::IpAddr>().unwrap(),
                4321,
            ))));
        spoofed
            .headers_mut()
            .insert("x-forwarded-proto", HeaderValue::from_static("https"));
        spoofed
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        let response = service.call(spoofed).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
