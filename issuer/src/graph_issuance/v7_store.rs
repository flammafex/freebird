// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable storage for the native V7 graph-operation namespace.

use anyhow::{Context, Result};
use rand::{rngs::OsRng, RngCore};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const PREFIX: &str = "freebird:native-graph-issuance:v7:";
const SCHEMA: &[u8] = b"freebird/native-graph-operation/v7";
const REPLAY_DOMAIN: &[u8] = b"freebird native graph replay identity v7\0";
pub const LEASE_SECS: u64 = 30;

// The operation and its one-use authorization marker are written by one Lua
// invocation.  The marker has no expiry and is deliberately never released.
const RESERVE: &str = r#"
local operation=KEYS[1]
if redis.call('EXISTS', operation)==1 then
  if redis.call('HGET',operation,'schema')~='freebird/native-graph-operation/v7' then return 5 end
  if redis.call('HGET',operation,'request_digest')~=ARGV[1]
     or redis.call('HGET',operation,'canonical_request')~=ARGV[2]
     or redis.call('HGET',operation,'replay_identity')~=ARGV[3]
     or redis.call('HGET',operation,'global_spend_key')~=ARGV[4]
     or redis.call('HGET',operation,'request')~=ARGV[5] then return 2 end
  if redis.call('HGET',operation,'state')=='committed' then return 1 end
  if redis.call('HGET',operation,'state')=='reserved' then return 3 end
  return 5
end
if redis.call('EXISTS',KEYS[2])==1 then return 4 end
local now=tonumber(redis.call('TIME')[1])
if redis.call('SETNX',KEYS[2],ARGV[4])~=1 then return 4 end
redis.call('HSET',operation,
  'schema','freebird/native-graph-operation/v7',
  'request',ARGV[5],
  'canonical_request',ARGV[2],
  'request_digest',ARGV[1],
  'replay_identity',ARGV[3],
  'global_spend_key',ARGV[4],
  'state','reserved',
  'fence',ARGV[6],
  'lease_until',now+tonumber(ARGV[7]),
  'created_at',now)
return 0
"#;

const CLAIM: &str = r#"
local state=redis.call('HGET',KEYS[1],'state')
if not state then return 3 end
if redis.call('HGET',KEYS[1],'schema')~='freebird/native-graph-operation/v7' then return 5 end
if state=='committed' then return 4 end
if state~='reserved' then return 5 end
local now=tonumber(redis.call('TIME')[1])
if tonumber(redis.call('HGET',KEYS[1],'lease_until'))>now then return 1 end
redis.call('HSET',KEYS[1],'fence',ARGV[1],'lease_until',now+tonumber(ARGV[2]))
return 0
"#;

const COMMIT: &str = r#"
local state=redis.call('HGET',KEYS[1],'state')
if not state then return 3 end
if redis.call('HGET',KEYS[1],'schema')~='freebird/native-graph-operation/v7' then return 3 end
if redis.call('HGET',KEYS[1],'request_digest')~=ARGV[1] then return 2 end
if state=='committed' then
  if redis.call('HGET',KEYS[1],'response')==ARGV[3] then return 1 else return 2 end
end
if state~='reserved' then return 3 end
if redis.call('HGET',KEYS[1],'fence')~=ARGV[2] then return 4 end
redis.call('HSET',KEYS[1],'state','committed','response',ARGV[3])
return 0
"#;

#[derive(Clone)]
pub(super) struct V7GraphIssuanceStore {
    client: redis::Client,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum V7State {
    Reserved,
    Committed,
}

#[derive(Debug)]
pub(super) struct StoredV7Operation {
    pub(super) request: Vec<u8>,
    pub(super) canonical_request: Vec<u8>,
    pub(super) request_digest: [u8; 32],
    pub(super) replay_identity: String,
    pub(super) global_spend_key: String,
    pub(super) state: V7State,
    pub(super) fence: Vec<u8>,
    pub(super) lease_until: u64,
    pub(super) response: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(super) struct V7Reservation {
    pub(super) fence: Vec<u8>,
}

pub(super) enum V7ReserveOutcome {
    Created(V7Reservation),
    Existing(Box<StoredV7Operation>),
    Conflict,
    AuthorizationUsed,
    InProgress,
}

pub(super) enum V7ClaimOutcome {
    Claimed(V7Reservation),
    Live,
    Committed,
    Missing,
    InvalidState,
}

pub(super) enum V7TransitionOutcome {
    Applied,
    Repeated,
    Conflict,
    InvalidState,
    StaleFence,
}

impl V7GraphIssuanceStore {
    pub(super) fn new(redis_url: &str) -> Result<Self> {
        Ok(Self {
            client: redis::Client::open(redis_url)?,
        })
    }

    pub(super) async fn readiness_check(&self) -> Result<()> {
        let mut connection = self.client.get_async_connection().await?;
        let _: String = redis::cmd("PING").query_async(&mut connection).await?;
        Ok(())
    }

    pub(super) fn operation_key(operation_id: &[u8; 16]) -> String {
        format!("{PREFIX}operation:{}", hex::encode(operation_id))
    }

    pub(super) fn authorization_key(global_spend_key: &str) -> String {
        global_spend_key.to_owned()
    }

    pub(super) fn replay_identity(global_spend_key: &str, nullifier_digest: &[u8; 32]) -> String {
        let mut transcript = Vec::with_capacity(
            REPLAY_DOMAIN.len() + 4 + global_spend_key.len() + nullifier_digest.len(),
        );
        transcript.extend_from_slice(REPLAY_DOMAIN);
        transcript.extend_from_slice(&(global_spend_key.len() as u32).to_be_bytes());
        transcript.extend_from_slice(global_spend_key.as_bytes());
        transcript.extend_from_slice(nullifier_digest);
        hex::encode(Sha256::digest(transcript))
    }

    fn fence() -> Vec<u8> {
        let mut fence = vec![0; 32];
        OsRng.fill_bytes(&mut fence);
        fence
    }

    pub(super) async fn get(&self, operation_id: &[u8; 16]) -> Result<Option<StoredV7Operation>> {
        let mut connection = self.client.get_async_connection().await?;
        let values: HashMap<Vec<u8>, Vec<u8>> = connection
            .hgetall(Self::operation_key(operation_id))
            .await?;
        if values.is_empty() {
            return Ok(None);
        }
        let required = |name: &[u8]| {
            values
                .get(name)
                .cloned()
                .with_context(|| format!("incomplete V7 graph operation field {:?}", name))
        };
        if required(b"schema")?.as_slice() != SCHEMA {
            anyhow::bail!("invalid V7 graph operation schema")
        }
        let digest = |name: &[u8]| -> Result<[u8; 32]> {
            required(name)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid V7 graph operation digest"))
        };
        let number = |name: &[u8]| -> Result<u64> {
            String::from_utf8(required(name)?)?
                .parse()
                .context("invalid V7 graph operation number")
        };
        let state = match required(b"state")?.as_slice() {
            b"reserved" => V7State::Reserved,
            b"committed" => V7State::Committed,
            _ => anyhow::bail!("invalid V7 graph operation state"),
        };
        let response = values.get(b"response".as_slice()).cloned();
        if state == V7State::Committed && response.is_none() {
            anyhow::bail!("committed V7 graph operation response is missing")
        }
        Ok(Some(StoredV7Operation {
            request: required(b"request")?,
            canonical_request: required(b"canonical_request")?,
            request_digest: digest(b"request_digest")?,
            replay_identity: String::from_utf8(required(b"replay_identity")?)?,
            global_spend_key: String::from_utf8(required(b"global_spend_key")?)?,
            state,
            fence: required(b"fence")?,
            lease_until: number(b"lease_until")?,
            response,
        }))
    }

    pub(super) async fn reserve_authorization(
        &self,
        operation_id: &[u8; 16],
        request: &[u8],
        canonical_request: &[u8],
        request_digest: &[u8; 32],
        global_spend_key: &str,
        replay_identity: &str,
    ) -> Result<V7ReserveOutcome> {
        if request.is_empty() || canonical_request.is_empty() {
            anyhow::bail!("invalid V7 reservation request bounds")
        }
        let fence = Self::fence();
        let mut connection = self.client.get_async_connection().await?;
        let code: i64 = redis::Script::new(RESERVE)
            .key(Self::operation_key(operation_id))
            .key(Self::authorization_key(global_spend_key))
            .arg(request_digest.as_slice())
            .arg(canonical_request)
            .arg(replay_identity)
            .arg(global_spend_key)
            .arg(request)
            .arg(&fence)
            .arg(LEASE_SECS)
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => V7ReserveOutcome::Created(V7Reservation { fence }),
            1 => V7ReserveOutcome::Existing(Box::new(
                self.get(operation_id)
                    .await?
                    .context("existing V7 graph operation disappeared")?,
            )),
            2 => V7ReserveOutcome::Conflict,
            3 => V7ReserveOutcome::InProgress,
            4 => V7ReserveOutcome::AuthorizationUsed,
            5 => anyhow::bail!("invalid V7 graph operation schema or state"),
            _ => anyhow::bail!("invalid V7 graph authorization reservation result"),
        })
    }

    pub(super) async fn claim(&self, operation_id: &[u8; 16]) -> Result<V7ClaimOutcome> {
        let fence = Self::fence();
        let mut connection = self.client.get_async_connection().await?;
        let code: i64 = redis::Script::new(CLAIM)
            .key(Self::operation_key(operation_id))
            .arg(&fence)
            .arg(LEASE_SECS)
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => V7ClaimOutcome::Claimed(V7Reservation { fence }),
            1 => V7ClaimOutcome::Live,
            3 => V7ClaimOutcome::Missing,
            4 => V7ClaimOutcome::Committed,
            5 => V7ClaimOutcome::InvalidState,
            _ => anyhow::bail!("invalid V7 graph claim result"),
        })
    }

    pub(super) async fn commit(
        &self,
        operation_id: &[u8; 16],
        request_digest: &[u8; 32],
        fence: &[u8],
        response: &[u8],
    ) -> Result<V7TransitionOutcome> {
        let mut connection = self.client.get_async_connection().await?;
        let code: i64 = redis::Script::new(COMMIT)
            .key(Self::operation_key(operation_id))
            .arg(request_digest.as_slice())
            .arg(fence)
            .arg(response)
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => V7TransitionOutcome::Applied,
            1 => V7TransitionOutcome::Repeated,
            2 => V7TransitionOutcome::Conflict,
            3 => V7TransitionOutcome::InvalidState,
            4 => V7TransitionOutcome::StaleFence,
            _ => anyhow::bail!("invalid V7 graph commit result"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        V7ClaimOutcome, V7GraphIssuanceStore, V7ReserveOutcome, V7State, V7TransitionOutcome,
    };
    use redis::AsyncCommands;

    #[test]
    fn replay_identity_is_stable_and_domain_separated() {
        let identity = V7GraphIssuanceStore::replay_identity("global:test", &[7; 32]);
        assert_eq!(identity.len(), 64);
        assert_eq!(
            identity,
            V7GraphIssuanceStore::replay_identity("global:test", &[7; 32])
        );
        assert_ne!(
            identity,
            V7GraphIssuanceStore::replay_identity("global:test", &[8; 32])
        );
        assert_ne!(
            identity,
            V7GraphIssuanceStore::replay_identity("global:other", &[7; 32])
        );
    }

    #[tokio::test]
    #[ignore = "requires FREEBIRD_REDIS_LIVE_URL pointing to a disposable Redis instance"]
    async fn redis_state_machine_covers_retry_reuse_claim_and_recovery() {
        let url = std::env::var("FREEBIRD_REDIS_LIVE_URL").expect("live Redis URL");
        let store = V7GraphIssuanceStore::new(&url).unwrap();
        let suffix = uuid::Uuid::new_v4().to_string();
        let operation = [0x31; 16];
        let other_operation = [0x32; 16];
        let global = format!("freebird:test:v7:global:{suffix}");
        let operation_key = V7GraphIssuanceStore::operation_key(&operation);
        let other_key = V7GraphIssuanceStore::operation_key(&other_operation);
        let auth_key = V7GraphIssuanceStore::authorization_key(&global);
        let mut connection = store.client.get_async_connection().await.unwrap();
        let _: i64 = redis::cmd("DEL")
            .arg(&operation_key)
            .arg(&other_key)
            .arg(&auth_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        drop(connection);

        let digest = [9; 32];
        let created = store
            .reserve_authorization(
                &operation,
                b"json",
                b"canonical",
                &digest,
                &global,
                "replay",
            )
            .await
            .unwrap();
        let fence = match created {
            V7ReserveOutcome::Created(reservation) => reservation.fence,
            _ => panic!("expected created reservation"),
        };
        let mut marker_connection = store.client.get_async_connection().await.unwrap();
        let marker: Vec<u8> = redis::cmd("GET")
            .arg(&auth_key)
            .query_async(&mut marker_connection)
            .await
            .unwrap();
        drop(marker_connection);
        assert_eq!(marker, global.as_bytes());
        assert!(matches!(
            store.get(&operation).await.unwrap().unwrap().state,
            V7State::Reserved
        ));
        assert!(matches!(
            store
                .reserve_authorization(
                    &operation,
                    b"json",
                    b"canonical",
                    &digest,
                    &global,
                    "replay"
                )
                .await
                .unwrap(),
            V7ReserveOutcome::InProgress
        ));
        assert!(matches!(
            store
                .reserve_authorization(
                    &operation,
                    b"other",
                    b"canonical",
                    &digest,
                    &global,
                    "replay"
                )
                .await
                .unwrap(),
            V7ReserveOutcome::Conflict
        ));
        assert!(matches!(
            store
                .reserve_authorization(
                    &other_operation,
                    b"json",
                    b"canonical",
                    &digest,
                    &global,
                    "replay"
                )
                .await
                .unwrap(),
            V7ReserveOutcome::AuthorizationUsed
        ));

        let mut connection = store.client.get_async_connection().await.unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg(&operation_key)
            .arg("lease_until")
            .arg(0)
            .query_async(&mut connection)
            .await
            .unwrap();
        drop(connection);
        let (first_claim, second_claim) =
            tokio::join!(store.claim(&operation), store.claim(&operation),);
        let recovered_fence = match (first_claim, second_claim) {
            (Ok(V7ClaimOutcome::Claimed(reservation)), Ok(V7ClaimOutcome::Live))
            | (Ok(V7ClaimOutcome::Live), Ok(V7ClaimOutcome::Claimed(reservation))) => {
                reservation.fence
            }
            _ => panic!("expected exactly one expired reservation claimant"),
        };
        assert!(matches!(
            store
                .commit(&operation, &digest, &fence, b"stale")
                .await
                .unwrap(),
            V7TransitionOutcome::StaleFence
        ));
        assert!(matches!(
            store
                .commit(&operation, &digest, &recovered_fence, b"response")
                .await
                .unwrap(),
            V7TransitionOutcome::Applied
        ));
        assert!(matches!(
            store.get(&operation).await.unwrap().unwrap().state,
            V7State::Committed
        ));
        assert_eq!(
            store
                .get(&operation)
                .await
                .unwrap()
                .unwrap()
                .response
                .as_deref(),
            Some(b"response".as_slice())
        );
        assert!(matches!(
            store
                .commit(&operation, &digest, &recovered_fence, b"response")
                .await
                .unwrap(),
            V7TransitionOutcome::Repeated
        ));
        assert!(matches!(
            store.claim(&operation).await.unwrap(),
            V7ClaimOutcome::Committed
        ));

        let mut connection = store.client.get_async_connection().await.unwrap();
        let _: i64 = redis::cmd("DEL")
            .arg(&operation_key)
            .arg(&other_key)
            .arg(&auth_key)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
}
