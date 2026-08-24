use base64ct::Encoding;
use freebird_common::api::V4ReplayAuthorityDiscovery;

#[test]
fn replay_authority_discovery_requires_canonical_unique_32_byte_values() {
    let authority = base64ct::Base64UrlUnpadded::encode_string(&[7; 32]);
    let scope = base64ct::Base64UrlUnpadded::encode_string(&[8; 32]);
    let discovery = V4ReplayAuthorityDiscovery {
        issuer_id: "issuer:test".into(),
        authority_id: authority,
        v4_scope_digest_tombstones: vec![scope.clone()],
    };
    assert!(discovery.validate().is_ok());

    let mut duplicate = discovery.clone();
    duplicate.v4_scope_digest_tombstones.push(scope);
    assert!(duplicate.validate().is_err());

    let mut padded = discovery;
    padded.authority_id.push('=');
    assert!(padded.validate().is_err());
}
