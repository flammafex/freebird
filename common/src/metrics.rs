use axum::body::Body;
use axum::http::{Request, Response};
use futures_util::future::BoxFuture;
use lazy_static::lazy_static;
use prometheus::{histogram_opts, opts, Encoder, HistogramVec, IntCounterVec, Registry};
use std::task::{Context, Poll};
use tower::Layer;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref REQUEST_DURATION: HistogramVec = HistogramVec::new(
        histogram_opts!(
            "freebird_request_duration_seconds",
            "Request duration in seconds",
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        ),
        &["method", "path"]
    )
    .unwrap();
    pub static ref REQUEST_ERRORS: IntCounterVec = IntCounterVec::new(
        opts!("freebird_request_errors_total", "Total request errors"),
        &["method", "path", "status_code"]
    )
    .unwrap();
}

pub fn register_metrics() {
    REGISTRY.register(Box::new(REQUEST_DURATION.clone())).ok();
    REGISTRY.register(Box::new(REQUEST_ERRORS.clone())).ok();
}

pub fn encode_metrics() -> String {
    let mut buffer = Vec::new();
    let encoder = prometheus::TextEncoder::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer).ok();
    String::from_utf8(buffer).unwrap_or_default()
}

pub fn record_request(method: &str, path: &str, status_code: u16, duration_secs: f64) {
    REQUEST_DURATION
        .with_label_values(&[method, path])
        .observe(duration_secs);
    if status_code >= 400 {
        REQUEST_ERRORS
            .with_label_values(&[method, path, &status_code.to_string()])
            .inc();
    }
}

#[derive(Clone)]
pub struct MetricsMiddleware;

impl<S> Layer<S> for MetricsMiddleware {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService { inner }
    }
}

#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
}

impl<S> tower::Service<Request<Body>> for MetricsService<S>
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
        let method = req.method().clone().to_string();
        let path = req.uri().path().to_string();
        let start = std::time::Instant::now();

        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            let response = inner.call(req).await?;
            let duration = start.elapsed().as_secs_f64();
            let status = response.status().as_u16();
            record_request(&method, &path, status, duration);
            Ok(response)
        })
    }
}
