// SPDX-License-Identifier: Apache-2.0 OR MIT
//! V7-only durable exchange work and replay state.

use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const PREFIX_V7: &str = "freebird:exchange:v7:";
const SPENT_PREFIX_V7: &str = "freebird:spent:v7:";
const STATUS_DOMAIN_V7: &[u8] = b"freebird exchange status capability v7\0";
pub const LEASE_SECS_V7: u64 = 30;

const RESERVE_V7: &str = r#"
local op=KEYS[1]
if redis.call('EXISTS',op)==1 then
  if redis.call('HGET',op,'schema')~='freebird-exchange-v7' then return 7 end
  if redis.call('HGET',op,'request_digest')~=ARGV[1] then return 2 end
  if redis.call('HGET',op,'status_capability_digest')~=ARGV[2] then return 3 end
  return 1
end
local n=tonumber(ARGV[3]); if not n or n<1 then return 6 end
local seen={}
for i=1,n do
  local key=KEYS[1+i]
  if seen[key] then return 4 end
  seen[key]=true
  if redis.call('EXISTS',key)==1 then return 5 end
end
local now=tonumber(redis.call('TIME')[1])
local fence=ARGV[4]
for i=1,n do
  redis.call('SET',KEYS[1+i],ARGV[1],'NX')
end
redis.call('HSET',op,
  'schema','freebird-exchange-v7',
  'receipt_key_id',ARGV[5],
  'request',ARGV[6],
  'request_digest',ARGV[1],
  'status_capability_digest',ARGV[2],
  'state','1',
  'fence',fence,
  'lease_until',now+tonumber(ARGV[7]),
  'created_at',now)
return 0
"#;

const CLAIM_V7: &str = r#"
local state=redis.call('HGET',KEYS[1],'state')
if not state then return 3 end
if redis.call('HGET',KEYS[1],'schema')~='freebird-exchange-v7' then return 5 end
if state=='3' then return 4 end
if state~='1' and state~='2' then return 5 end
local now=tonumber(redis.call('TIME')[1])
if tonumber(redis.call('HGET',KEYS[1],'lease_until'))>now then return 1 end
local fence=ARGV[1]
redis.call('HSET',KEYS[1],'fence',fence,'lease_until',now+tonumber(ARGV[2]))
return 0
"#;

const RESULT_V7: &str = r#"
local state=redis.call('HGET',KEYS[1],'state')
if not state then return 3 end
if redis.call('HGET',KEYS[1],'schema')~='freebird-exchange-v7' then return 3 end
if state=='2' or state=='3' then
  if redis.call('HGET',KEYS[1],'result')==ARGV[2] and redis.call('HGET',KEYS[1],'result_digest')==ARGV[3] then return 1 else return 2 end
end
if state~='1' then return 3 end
if redis.call('HGET',KEYS[1],'fence')~=ARGV[1] then return 4 end
redis.call('HSET',KEYS[1],'state','2','result',ARGV[2],'result_digest',ARGV[3])
return 0
"#;

const COMMIT_V7: &str = r#"
local state=redis.call('HGET',KEYS[1],'state')
if not state then return 3 end
if redis.call('HGET',KEYS[1],'schema')~='freebird-exchange-v7' then return 3 end
if state=='3' then
  if redis.call('HGET',KEYS[1],'receipt')==ARGV[2] and redis.call('HGET',KEYS[1],'response')==ARGV[3] then return 1 else return 2 end
end
if state~='2' then return 3 end
if redis.call('HGET',KEYS[1],'fence')~=ARGV[1] then return 4 end
redis.call('HSET',KEYS[1],'state','3','receipt',ARGV[2],'response',ARGV[3])
return 0
"#;

#[derive(Clone)]
pub struct V7ExchangeStore {
    client: redis::Client,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V7State {
    Reserved,
    ResultReady,
    Committed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V7Reservation {
    pub fence: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V7ReserveOutcome {
    Created(V7Reservation),
    Existing(Box<V7OperationRecord>),
    Conflict,
    CapabilityMismatch,
    DuplicateSource,
    Spent,
    InvalidSchema,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V7ClaimOutcome {
    Claimed(V7Reservation),
    Live,
    Committed,
    Missing,
    InvalidState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V7TransitionOutcome {
    Applied,
    Repeated,
    Conflict,
    InvalidState,
    StaleFence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V7OperationRecord {
    pub request: Vec<u8>,
    pub receipt_key_id: String,
    pub request_digest: [u8; 32],
    pub status_capability_digest: [u8; 32],
    pub state: V7State,
    pub fence: Vec<u8>,
    pub created_at: u64,
    pub lease_until: u64,
    pub result: Option<Vec<u8>>,
    pub result_digest: Option<[u8; 32]>,
    pub receipt: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}

impl V7ExchangeStore {
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self {
            client: redis::Client::open(url)?,
        })
    }

    /// Perform a non-mutating store health check for readiness.
    pub async fn readiness_check(&self) -> Result<()> {
        let mut connection = self.conn().await?;
        let _: String = redis::cmd("PING").query_async(&mut connection).await?;
        Ok(())
    }

    async fn conn(&self) -> Result<redis::aio::Connection> {
        Ok(self.client.get_async_connection().await?)
    }

    pub fn operation_key(operation_id: &[u8; 16]) -> String {
        format!("{PREFIX_V7}op:{}", hex::encode(operation_id))
    }

    /// Canonical V7 replay identity: federation namespace plus body nullifier.
    pub fn spent_key(issuer_or_federation_id: &str, body_nullifier: &[u8; 32]) -> String {
        format!(
            "{SPENT_PREFIX_V7}{issuer_or_federation_id}:{}",
            hex::encode(body_nullifier)
        )
    }

    pub fn status_capability_digest(capability: &[u8; 32]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(STATUS_DOMAIN_V7);
        digest.update(capability);
        digest.finalize().into()
    }

    fn fence() -> Vec<u8> {
        let mut fence = vec![0; 32];
        OsRng.fill_bytes(&mut fence);
        fence
    }

    pub async fn reserve(
        &self,
        operation_id: &[u8; 16],
        request: &[u8],
        request_digest: &[u8; 32],
        status_capability: &[u8; 32],
        spent_keys: &[String],
        receipt_key_id: &str,
    ) -> Result<V7ReserveOutcome> {
        if request.is_empty() || spent_keys.is_empty() {
            bail!("invalid V7 reservation bounds")
        }
        let mut unique = std::collections::HashSet::new();
        if spent_keys.iter().any(|key| !unique.insert(key)) {
            return Ok(V7ReserveOutcome::DuplicateSource);
        }
        let fence = Self::fence();
        let capability_digest = Self::status_capability_digest(status_capability);
        let script = redis::Script::new(RESERVE_V7);
        let mut invocation = script.prepare_invoke();
        invocation.key(Self::operation_key(operation_id));
        for key in spent_keys {
            invocation.key(key);
        }
        invocation
            .arg(request_digest.as_slice())
            .arg(capability_digest.as_slice())
            .arg(spent_keys.len())
            .arg(&fence)
            .arg(receipt_key_id)
            .arg(request)
            .arg(LEASE_SECS_V7);
        let mut connection = self.conn().await?;
        let code: i64 = invocation.invoke_async(&mut connection).await?;
        Ok(match code {
            0 => V7ReserveOutcome::Created(V7Reservation { fence }),
            1 => V7ReserveOutcome::Existing(Box::new(
                self.get(operation_id)
                    .await?
                    .context("existing V7 operation disappeared")?,
            )),
            2 => V7ReserveOutcome::Conflict,
            3 => V7ReserveOutcome::CapabilityMismatch,
            4 => V7ReserveOutcome::DuplicateSource,
            5 => V7ReserveOutcome::Spent,
            7 => V7ReserveOutcome::InvalidSchema,
            _ => bail!("invalid V7 reserve result"),
        })
    }

    pub async fn claim(&self, operation_id: &[u8; 16]) -> Result<V7ClaimOutcome> {
        let fence = Self::fence();
        let mut connection = self.conn().await?;
        let code: i64 = redis::Script::new(CLAIM_V7)
            .key(Self::operation_key(operation_id))
            .arg(&fence)
            .arg(LEASE_SECS_V7)
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => V7ClaimOutcome::Claimed(V7Reservation { fence }),
            1 => V7ClaimOutcome::Live,
            3 => V7ClaimOutcome::Missing,
            4 => V7ClaimOutcome::Committed,
            5 => V7ClaimOutcome::InvalidState,
            _ => bail!("invalid V7 claim result"),
        })
    }

    pub async fn result_ready(
        &self,
        operation_id: &[u8; 16],
        fence: &[u8],
        result: &[u8],
        digest: &[u8; 32],
    ) -> Result<V7TransitionOutcome> {
        self.transition(RESULT_V7, operation_id, &[fence, result, digest])
            .await
    }

    pub async fn commit(
        &self,
        operation_id: &[u8; 16],
        fence: &[u8],
        receipt: &[u8],
        response: &[u8],
    ) -> Result<V7TransitionOutcome> {
        self.transition(COMMIT_V7, operation_id, &[fence, receipt, response])
            .await
    }

    async fn transition(
        &self,
        script: &str,
        operation_id: &[u8; 16],
        args: &[&[u8]],
    ) -> Result<V7TransitionOutcome> {
        let script = redis::Script::new(script);
        let mut invocation = script.prepare_invoke();
        invocation.key(Self::operation_key(operation_id));
        for arg in args {
            invocation.arg(*arg);
        }
        let mut connection = self.conn().await?;
        let code: i64 = invocation.invoke_async(&mut connection).await?;
        Ok(match code {
            0 => V7TransitionOutcome::Applied,
            1 => V7TransitionOutcome::Repeated,
            2 => V7TransitionOutcome::Conflict,
            3 => V7TransitionOutcome::InvalidState,
            4 => V7TransitionOutcome::StaleFence,
            _ => bail!("invalid V7 transition result"),
        })
    }

    pub async fn get(&self, operation_id: &[u8; 16]) -> Result<Option<V7OperationRecord>> {
        let mut connection = self.conn().await?;
        let values: HashMap<Vec<u8>, Vec<u8>> = redis::cmd("HGETALL")
            .arg(Self::operation_key(operation_id))
            .query_async(&mut connection)
            .await?;
        if values.is_empty() {
            return Ok(None);
        }
        let required = |name: &[u8]| {
            values
                .get(name)
                .cloned()
                .with_context(|| format!("incomplete V7 operation field {:?}", name))
        };
        if required(b"schema")?.as_slice() != b"freebird-exchange-v7" {
            bail!("refusing non-V7 exchange operation record")
        }
        let array = |name: &[u8]| -> Result<[u8; 32]> {
            required(name)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid V7 digest"))
        };
        let number = |name: &[u8]| -> Result<u64> {
            String::from_utf8(required(name)?)?
                .parse()
                .context("invalid V7 number")
        };
        let state = match required(b"state")?.as_slice() {
            b"1" => V7State::Reserved,
            b"2" => V7State::ResultReady,
            b"3" => V7State::Committed,
            _ => bail!("invalid V7 operation state"),
        };
        let optional = |name: &[u8]| values.get(name).cloned();
        let result_digest = values
            .get(b"result_digest".as_slice())
            .map(|value| {
                value
                    .clone()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid V7 result digest"))
            })
            .transpose()?;
        Ok(Some(V7OperationRecord {
            request: required(b"request")?,
            receipt_key_id: String::from_utf8(required(b"receipt_key_id")?)?,
            request_digest: array(b"request_digest")?,
            status_capability_digest: array(b"status_capability_digest")?,
            state,
            fence: required(b"fence")?,
            created_at: number(b"created_at")?,
            lease_until: number(b"lease_until")?,
            result: optional(b"result"),
            result_digest,
            receipt: optional(b"receipt"),
            response: optional(b"response"),
        }))
    }
}
