//! Exercise the real handler spans, including early rejection, without a global subscriber.
use super::*;
use freebird_common::api::{BatchIssueReq, NativeBearerV7BatchIssueReq, NativeBearerV7IssueReq};
use std::collections::BTreeMap;
use std::sync::Mutex;
use tracing::{field::Visit, instrument::WithSubscriber, span, Subscriber};
use tracing_subscriber::{layer::Context, prelude::*, Layer};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<BTreeMap<String, BTreeMap<String, String>>>>);

struct Fields<'a>(&'a mut BTreeMap<String, String>);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}

impl<S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>> Layer<S> for Capture {
    fn on_new_span(&self, attrs: &span::Attributes<'_>, _: &span::Id, _: Context<'_, S>) {
        let mut spans = self.0.lock().unwrap();
        let fields = spans.entry(attrs.metadata().name().into()).or_default();
        // Check declared fields too, even if their values were never recorded.
        for field in attrs.metadata().fields() {
            fields.insert(field.name().into(), String::new());
        }
        attrs.record(&mut Fields(fields));
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).unwrap();
        let mut spans = self.0.lock().unwrap();
        values.record(&mut Fields(spans.entry(span.name().into()).or_default()));
    }
}

#[tokio::test]
async fn issuance_handler_spans_exclude_private_inputs() {
    const REQUEST: &str = "private-request-sentinel!";
    const CONTEXT: &str = "private-context-sentinel!";
    const PROOF: &str = "private-proof-sentinel";
    const SOCKET_IP: &str = "192.0.2.123";
    const VALIDATED_IP: &str = "198.51.100.231";

    let state = Arc::new(AppStateWithSybil {
        issuer_id: "test-issuer".into(),
        kid: "safe-kid".into(),
        pubkey_b64: String::new(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        admission: Default::default(),
        invitation_system: None,
        native_bearer_v7: crate::main_state::test_native_bearer_v7(),
        native_bearer_v7_retained: vec![],
        native_exchange_v7: None,
        native_exchange_v7_discovery: None,
        native_graph_issuance_v7: None,
        native_graph_issuance_v7_discovery: None,
        replay_authority: None,
        epoch_duration_sec: 86400,
        epoch_retention: 1,
        admin_api_key: None,
        sybil_summary: None,
    });
    let voprf = Arc::new(
        MultiKeyVoprfCore::new([1; 32], String::new(), "safe-kid".into(), b"test").unwrap(),
    );
    let capture = Capture::default();
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(capture.clone()));
    let proof = || {
        Some(SybilProof::RegisteredUser {
            user_id: PROOF.into(),
        })
    };
    let issue_req = || IssueReq {
        blinded_element_b64: REQUEST.into(),
        ctx_b64: Some(CONTEXT.into()),
        sybil_proof: proof(),
    };

    macro_rules! invoke {
        ($handler:path, $req:expr) => {
            $handler(
                State((state.clone(), voprf.clone())),
                Some(ConnectInfo(format!("{SOCKET_IP}:43210").parse().unwrap())),
                Some(Extension(ValidatedClientIp(VALIDATED_IP.parse().unwrap()))),
                HeaderMap::new(),
                Json($req),
            )
            .with_subscriber(dispatch.clone())
            .await
        };
    }

    assert!(invoke!(super::handle, issue_req()).is_err());
    assert!(invoke!(super::renew, issue_req()).is_err());
    // Oversized batch rejects before evaluation while still carrying private inputs.
    assert!(invoke!(
        crate::routes::batch_issue::handle_batch,
        BatchIssueReq {
            blinded_elements: vec![REQUEST.into(); crate::routes::batch_issue::MAX_BATCH_SIZE + 1],
            ctx_b64: Some(CONTEXT.into()),
            sybil_proof: proof(),
        }
    )
    .is_err());
    assert!(invoke!(
        crate::routes::native_bearer_v7::handle,
        NativeBearerV7IssueReq {
            token_key_id: "01".repeat(32),
            blinded_msg_b64: REQUEST.into(),
            sybil_proof: proof(),
        }
    )
    .is_err());
    assert!(invoke!(
        crate::routes::native_bearer_v7::handle_batch,
        NativeBearerV7BatchIssueReq {
            token_key_id: "01".repeat(32),
            blinded_msgs_b64: vec![REQUEST.into()],
            sybil_proof: proof(),
        }
    )
    .is_err());

    let spans = capture.0.lock().unwrap();
    for (name, expected) in [
        ("issue_token", vec!["has_proof", "kid", "sybil_configured"]),
        ("renew_token", vec!["has_proof", "kid", "sybil_configured"]),
        ("handle_batch", vec!["batch_size"]),
        ("issue_native_bearer_v7", vec![]),
        ("issue_native_bearer_v7_batch", vec![]),
    ] {
        let fields = spans
            .get(name)
            .unwrap_or_else(|| panic!("missing span {name}"));
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            expected,
            "{name}"
        );
        for sentinel in [REQUEST, CONTEXT, PROOF, SOCKET_IP, VALIDATED_IP] {
            assert!(
                !format!("{fields:?}").contains(sentinel),
                "{name} leaked {sentinel}"
            );
        }
    }
    for name in ["issue_token", "renew_token"] {
        assert_eq!(spans[name]["has_proof"], "true");
        assert_eq!(spans[name]["kid"], "\"safe-kid\"");
        assert_eq!(spans[name]["sybil_configured"], "false");
    }
    assert_eq!(
        spans["handle_batch"]["batch_size"],
        (crate::routes::batch_issue::MAX_BATCH_SIZE + 1).to_string()
    );
}
