// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable storage for the native V7 graph-operation namespace.

use anyhow::{Context, Result};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};

const PREFIX: &str = "freebird:native-graph-issuance:v7:";
const SCHEMA: &[u8] = b"freebird/native-graph-operation/v7";
const REPLAY_DOMAIN: &[u8] = b"freebird native graph replay identity v7\0";

const RESERVE_AUTHORIZATION: &str = r#"
local operation=KEYS[1]
if redis.call('EXISTS', operation)==1 then
  if redis.call('HGET', operation, 'request_digest')~=ARGV[1] then return 2 end
  local state=redis.call('HGET', operation, 'state')
  if state=='committed' then return 1 end
  return 3
end
if redis.call('EXISTS',KEYS[2])==1 then return 4 end
redis.call('SET',KEYS[2],ARGV[1])
redis.call('HSET',operation,
  'schema','freebird/native-graph-operation/v7',
  'request_digest',ARGV[1],
  'replay_identity',ARGV[2],
  'state','reserved')
return 0
"#;

const COMMIT: &str = r#"
local operation=KEYS[1]
if redis.call('EXISTS',operation)==0 then return 2 end
if redis.call('HGET',operation,'request_digest')~=ARGV[1] then return 2 end
local state=redis.call('HGET',operation,'state')
if state=='committed' then return 1 end
if state~='reserved' then return 2 end
redis.call('HSET',operation,'state','committed','response',ARGV[2])
return 0
"#;

const RELEASE: &str = r#"
local operation=KEYS[1]
if redis.call('EXISTS',operation)==0 then return 0 end
if redis.call('HGET',operation,'request_digest')~=ARGV[1] then return 1 end
if redis.call('HGET',operation,'state')~='reserved' then return 1 end
if redis.call('GET',KEYS[2])~=ARGV[1] then return 1 end
redis.call('DEL',KEYS[2],operation)
return 0
"#;

#[derive(Clone)]
pub(super) struct V7GraphIssuanceStore {
    client: redis::Client,
}

#[derive(Debug)]
pub(super) struct StoredV7Operation {
    pub(super) request_digest: [u8; 32],
    pub(super) replay_identity: String,
    pub(super) response: Vec<u8>,
}

pub(super) enum V7ReserveOutcome {
    Created,
    Existing(Box<StoredV7Operation>),
    Conflict,
    AuthorizationUsed,
    InProgress,
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

    pub(super) async fn get(&self, operation_id: &[u8; 16]) -> Result<Option<StoredV7Operation>> {
        let mut connection = self.client.get_async_connection().await?;
        let values: std::collections::HashMap<Vec<u8>, Vec<u8>> = connection
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
        if required(b"state")?.as_slice() != b"committed" {
            anyhow::bail!("V7 graph operation is still reserved")
        }
        Ok(Some(StoredV7Operation {
            request_digest: required(b"request_digest")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid V7 graph request digest"))?,
            replay_identity: String::from_utf8(required(b"replay_identity")?)?,
            response: required(b"response")?,
        }))
    }

    pub(super) async fn reserve_authorization(
        &self,
        operation_id: &[u8; 16],
        request_digest: &[u8; 32],
        global_spend_key: &str,
        replay_identity: &str,
    ) -> Result<V7ReserveOutcome> {
        let mut connection = self.client.get_async_connection().await?;
        let code: i64 = redis::Script::new(RESERVE_AUTHORIZATION)
            .key(Self::operation_key(operation_id))
            .key(Self::authorization_key(global_spend_key))
            .arg(request_digest.as_slice())
            .arg(replay_identity)
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => V7ReserveOutcome::Created,
            1 => V7ReserveOutcome::Existing(Box::new(
                self.get(operation_id)
                    .await?
                    .context("existing V7 graph operation disappeared")?,
            )),
            2 => V7ReserveOutcome::Conflict,
            3 => V7ReserveOutcome::InProgress,
            4 => V7ReserveOutcome::AuthorizationUsed,
            _ => anyhow::bail!("invalid V7 graph authorization reservation result"),
        })
    }

    pub(super) async fn commit(
        &self,
        operation_id: &[u8; 16],
        request_digest: &[u8; 32],
        response: &[u8],
    ) -> Result<()> {
        let mut connection = self.client.get_async_connection().await?;
        let code: i64 = redis::Script::new(COMMIT)
            .key(Self::operation_key(operation_id))
            .arg(request_digest.as_slice())
            .arg(response)
            .invoke_async(&mut connection)
            .await?;
        if code != 0 && code != 1 {
            anyhow::bail!("V7 graph operation commit conflict")
        }
        Ok(())
    }

    pub(super) async fn release_authorization(
        &self,
        operation_id: &[u8; 16],
        request_digest: &[u8; 32],
        global_spend_key: &str,
    ) -> Result<()> {
        let mut connection = self.client.get_async_connection().await?;
        let code: i64 = redis::Script::new(RELEASE)
            .key(Self::operation_key(operation_id))
            .key(Self::authorization_key(global_spend_key))
            .arg(request_digest.as_slice())
            .invoke_async(&mut connection)
            .await?;
        if code != 0 {
            anyhow::bail!("V7 graph authorization release conflict")
        }
        Ok(())
    }
}
