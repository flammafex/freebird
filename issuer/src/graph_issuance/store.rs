// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Graph issuance Redis reservation and replay-authority storage.

use anyhow::{bail, Context, Result};
use freebird_common::graph_issuance_api::{self, ReplayAuthorityProbeV1};
use rand::RngCore;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::policy::{policy_digest, GraphIssuancePolicy};

pub(super) const PREFIX: &str = "freebird:graph-issuance:v2:";
const STATUS_DOMAIN: &[u8] = b"freebird graph issuance status capability v2\0";
pub const REPLAY_AUTHORITY_ID_KEY: &str = "freebird:v4-replay-authority:v1:id";
pub(super) const REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY: &str =
    "freebird:v4-replay-authority:v1:scope-tombstones";
const REPLAY_AUTHORITY_PROBE_PREFIX: &str = "freebird:v4-replay-authority:v1:probe:";
const REPLAY_AUTHORITY_ACK_PREFIX: &str = "freebird:v4-replay-authority:v1:ack:";
pub(super) const REPLAY_AUTHORITY_PROBE_TTL_SECS: u64 = 30;

pub(super) fn status_digest(capability: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(STATUS_DOMAIN);
    hash.update(capability);
    hash.finalize().into()
}

const RESERVE: &str = r#"
local op=KEYS[1]
if redis.call('EXISTS',op)==1 then
  if redis.call('HGET',op,'request_digest')~=ARGV[1] then return 2 end
  if redis.call('HGET',op,'status_capability_digest')~=ARGV[2] then return 3 end
  return 1
end
local time_reply=redis.call('TIME')
if type(time_reply)~='table' or not time_reply[1] or not tonumber(time_reply[1]) then return 7 end
local now=tonumber(time_reply[1])
local descriptor_first=tonumber(ARGV[16]); local descriptor_last=tonumber(ARGV[17])
if not descriptor_first or not descriptor_last or descriptor_first>descriptor_last or
   now<descriptor_first or now>descriptor_last then return 7 end
local auth=KEYS[2]; local budget=KEYS[3]; local global_spend=KEYS[4]
local uses_global_spend=ARGV[15]=='1'
if uses_global_spend then
  if redis.call('EXISTS',global_spend)==1 then return 4 end
elseif redis.call('EXISTS',auth)==1 then return 4 end
if not string.match(ARGV[11],'^[0-9]+$') or not string.match(ARGV[12],'^[0-9]+$') then return 6 end
local quantity=tonumber(ARGV[11]); local limit=tonumber(ARGV[12])
if not quantity or not limit or quantity~=1 or limit<1 then return 6 end
local budget_type=redis.call('TYPE',budget)['ok']
if budget_type~='none' and budget_type~='hash' then return 5 end
local charged=0
if budget_type=='hash' then
  if redis.call('HGET',budget,'policy_digest')~=ARGV[10] or
     redis.call('HGET',budget,'policy_id')~=ARGV[3] or
     redis.call('HGET',budget,'limit')~=ARGV[12] or
     redis.call('HGET',budget,'charge_kind')~='issuance_quantity' then return 5 end
  local charged_raw=redis.call('HGET',budget,'charged')
  if not charged_raw or not string.match(charged_raw,'^[0-9]+$') then return 5 end
  charged=tonumber(charged_raw)
  if not charged or charged<0 or charged>limit then return 5 end
end
if quantity>limit-charged then return 6 end
-- No mutation is permitted above this line.
if uses_global_spend then
  redis.call('SET',global_spend,'1')
else
  redis.call('HSET',auth,'policy_id',ARGV[3],'authorization_nullifier_digest',ARGV[9],
    'request_digest',ARGV[1],'claimed','1')
end
if budget_type=='none' then
  redis.call('HSET',budget,'policy_id',ARGV[3],'policy_digest',ARGV[10],
    'limit',ARGV[12],'charge_kind','issuance_quantity','charged','0')
end
redis.call('HINCRBY',budget,'charged',ARGV[11])
redis.call('HSET',op,
  'request_digest',ARGV[1],'status_capability_digest',ARGV[2],
  'issuance_policy_id',ARGV[3],'graph_id',ARGV[4],'keyset_id',ARGV[5],
  'descriptor_id',ARGV[6],'signer_key_id',ARGV[7],
  'authorization_nullifier_digest',ARGV[9],'policy_digest',ARGV[10],
  'quantity',ARGV[11],'budget_id',ARGV[13],'state','committed',
  'blind_signature',ARGV[8],'response',ARGV[14])
return 0
"#;

// The authority identity check and challenge consumption are one Redis
// operation. A changed/deleted authority can therefore never consume a
// probe challenge.
const REPLAY_AUTHORITY_PROBE: &str = r#"
local authority=redis.call('GET',KEYS[1])
if redis.call('TTL',KEYS[1])~=-1 or not authority or string.len(authority)~=32 or authority~=ARGV[1] then
  return {1,''}
end
local challenge=redis.call('GETDEL',KEYS[2])
if not challenge then return {2,''} end
return {0,challenge}
"#;

#[derive(Clone)]
pub struct GraphIssuanceStore {
    client: redis::Client,
}

#[derive(Debug)]
pub(super) struct StoredOperation {
    pub(super) request_digest: [u8; 32],
    pub(super) status_capability_digest: [u8; 32],
    pub(super) issuance_policy_id: String,
    pub(super) graph_id: String,
    pub(super) keyset_id: String,
    pub(super) descriptor_id: String,
    pub(super) signer_key_id: String,
    pub(super) quantity: u32,
    pub(super) response: Vec<u8>,
}

pub(super) enum ReserveOutcome {
    Created,
    Existing(Box<StoredOperation>),
    Conflict,
    AuthorizationUsed,
    PolicyConflict,
    BudgetExhausted,
    DescriptorWindow,
}

impl GraphIssuanceStore {
    pub fn new(redis_url: &str) -> Result<Self> {
        Ok(Self {
            client: redis::Client::open(redis_url)?,
        })
    }

    async fn connection(&self) -> Result<redis::aio::Connection> {
        Ok(self.client.get_async_connection().await?)
    }

    pub async fn redis_time(&self) -> Result<i64> {
        let mut connection = self.connection().await?;
        let reply: Vec<String> = redis::cmd("TIME")
            .query_async(&mut connection)
            .await
            .context("invalid Redis TIME reply")?;
        let seconds = reply
            .first()
            .context("Redis TIME omitted seconds")?
            .parse::<i64>()
            .context("Redis TIME seconds are invalid")?;
        let micros = reply
            .get(1)
            .context("Redis TIME omitted microseconds")?
            .parse::<u32>()
            .context("Redis TIME microseconds are invalid")?;
        if reply.len() != 2 || micros >= 1_000_000 || seconds < 0 {
            bail!("Redis TIME descriptor validity reply is invalid")
        }
        Ok(seconds)
    }

    pub async fn initialize_replay_authority(
        &self,
        scopes: &[[u8; 32]],
    ) -> Result<([u8; 32], Vec<[u8; 32]>)> {
        let mut connection = self.connection().await?;
        let authority_type: String = redis::cmd("TYPE")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if authority_type != "none" && authority_type != "string" {
            bail!("replay authority identity has an invalid Redis type")
        }
        if authority_type == "string" {
            let ttl: i64 = redis::cmd("TTL")
                .arg(REPLAY_AUTHORITY_ID_KEY)
                .query_async(&mut connection)
                .await?;
            if ttl != -1 {
                bail!("replay authority identity must not expire")
            }
        }
        let _authority = if authority_type == "none" {
            let mut generated = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut generated);
            let created: Option<String> = redis::cmd("SET")
                .arg(REPLAY_AUTHORITY_ID_KEY)
                .arg(generated.as_slice())
                .arg("NX")
                .query_async(&mut connection)
                .await?;
            if created.is_some() {
                generated
            } else {
                let value: Vec<u8> = redis::cmd("GET")
                    .arg(REPLAY_AUTHORITY_ID_KEY)
                    .query_async(&mut connection)
                    .await?;
                value
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("replay authority identity is not 32 bytes"))?
            }
        } else {
            let value: Vec<u8> = redis::cmd("GET")
                .arg(REPLAY_AUTHORITY_ID_KEY)
                .query_async(&mut connection)
                .await?;
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("replay authority identity is not 32 bytes"))?
        };

        let tombstone_type: String = redis::cmd("TYPE")
            .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
            .query_async(&mut connection)
            .await?;
        if tombstone_type != "none" && tombstone_type != "hash" {
            bail!("replay authority scope tombstones have an invalid Redis type")
        }
        if tombstone_type == "hash" {
            let ttl: i64 = redis::cmd("TTL")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?;
            if ttl != -1 {
                bail!("replay authority scope tombstones must not expire")
            }
        }
        let existing: HashMap<Vec<u8>, Vec<u8>> = if tombstone_type == "hash" {
            redis::cmd("HGETALL")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?
        } else {
            HashMap::new()
        };
        let mut retained = Vec::with_capacity(existing.len() + scopes.len());
        for (field, value) in existing {
            let field_text = String::from_utf8(field).context("invalid scope tombstone field")?;
            let raw: [u8; 32] = hex::decode(&field_text)
                .context("invalid scope tombstone encoding")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("scope tombstone is not 32 bytes"))?;
            if hex::encode(raw) != field_text {
                bail!("scope tombstone encoding is not canonical")
            }
            if value.as_slice() != raw.as_slice() {
                bail!("scope tombstone value does not match its identity")
            }
            retained.push(raw);
        }
        for scope in scopes {
            if !retained.contains(scope) {
                retained.push(*scope);
            }
        }
        retained.sort_unstable();
        retained.dedup();
        if retained.len() > freebird_common::exchange_api::MAX_ITEMS {
            bail!("too many replay authority scope tombstones")
        }
        for scope in &retained {
            redis::cmd("HSET")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .arg(hex::encode(scope))
                .arg(scope.as_slice())
                .query_async::<_, i64>(&mut connection)
                .await?;
        }
        drop(connection);
        self.read_replay_authority_state().await
    }

    /// Read and validate the complete durable replay-authority container.
    /// Callers must use this rather than a startup snapshot when publishing
    /// discovery or determining readiness.
    pub async fn read_replay_authority_state(&self) -> Result<([u8; 32], Vec<[u8; 32]>)> {
        let mut connection = self.connection().await?;
        let authority_type: String = redis::cmd("TYPE")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if authority_type != "string" {
            bail!("replay authority identity is missing or has an invalid Redis type")
        }
        let authority_ttl: i64 = redis::cmd("TTL")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if authority_ttl != -1 {
            bail!("replay authority identity must not expire")
        }
        let authority: [u8; 32] = {
            let value: Vec<u8> = redis::cmd("GET")
                .arg(REPLAY_AUTHORITY_ID_KEY)
                .query_async(&mut connection)
                .await?;
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("replay authority identity is not 32 bytes"))?
        };
        let tombstone_type: String = redis::cmd("TYPE")
            .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
            .query_async(&mut connection)
            .await?;
        if tombstone_type != "none" && tombstone_type != "hash" {
            bail!("replay authority scope tombstones have an invalid Redis type")
        }
        if tombstone_type == "hash" {
            let tombstone_ttl: i64 = redis::cmd("TTL")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?;
            if tombstone_ttl != -1 {
                bail!("replay authority scope tombstones must not expire")
            }
        }
        let existing: HashMap<Vec<u8>, Vec<u8>> = if tombstone_type == "hash" {
            redis::cmd("HGETALL")
                .arg(REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?
        } else {
            HashMap::new()
        };
        if existing.len() > freebird_common::exchange_api::MAX_ITEMS {
            bail!("too many replay authority scope tombstones")
        }
        let mut tombstones = Vec::with_capacity(existing.len());
        for (field, value) in existing {
            let field_text = String::from_utf8(field).context("invalid scope tombstone field")?;
            let scope: [u8; 32] = hex::decode(&field_text)
                .context("invalid scope tombstone encoding")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("scope tombstone is not 32 bytes"))?;
            if hex::encode(scope) != field_text || value.as_slice() != scope.as_slice() {
                bail!("invalid replay authority scope tombstone")
            }
            tombstones.push(scope);
        }
        tombstones.sort_unstable();
        Ok((authority, tombstones))
    }

    pub fn probe_key(probe_id: &[u8; 32]) -> String {
        format!("{REPLAY_AUTHORITY_PROBE_PREFIX}{}", hex::encode(probe_id))
    }

    pub fn ack_key(probe_id: &[u8; 32]) -> String {
        format!("{REPLAY_AUTHORITY_ACK_PREFIX}{}", hex::encode(probe_id))
    }

    pub async fn replay_authority_probe(
        &self,
        probe: &ReplayAuthorityProbeV1,
        issuer_id: &str,
    ) -> Result<Option<[u8; 32]>> {
        let authority = probe.authority_id()?;
        let probe_id = probe.probe_id()?;
        let mut connection = self.connection().await?;
        let (code, challenge): (i64, Vec<u8>) = redis::Script::new(REPLAY_AUTHORITY_PROBE)
            .key(REPLAY_AUTHORITY_ID_KEY)
            .key(Self::probe_key(&probe_id))
            .arg(authority.as_slice())
            .invoke_async(&mut connection)
            .await?;
        if code == 1 {
            bail!("replay authority selector mismatch")
        }
        if code == 2 {
            return Ok(None);
        }
        if code != 0 {
            bail!("invalid replay authority probe result")
        }
        let challenge: [u8; 32] = challenge
            .try_into()
            .map_err(|_| anyhow::anyhow!("replay authority challenge is not 32 bytes"))?;
        let proof = graph_issuance_api::replay_authority_proof_v1(
            &challenge, &authority, &probe_id, issuer_id,
        )?;
        let ack: Option<String> = redis::cmd("SET")
            .arg(Self::ack_key(&probe_id))
            .arg(proof.as_slice())
            .arg("NX")
            .arg("EX")
            .arg(REPLAY_AUTHORITY_PROBE_TTL_SECS)
            .query_async(&mut connection)
            .await?;
        if ack.is_none() {
            bail!("replay authority acknowledgement already exists")
        }
        Ok(Some(proof))
    }

    pub(super) fn operation_key(operation_id: &[u8; 16]) -> String {
        format!("{PREFIX}op:{}", hex::encode(operation_id))
    }

    pub(super) fn no_global_spend_key(operation_id: &[u8; 16]) -> String {
        format!("{PREFIX}no-global-spend:{}", hex::encode(operation_id))
    }

    pub(super) async fn get(&self, operation_id: &[u8; 16]) -> Result<Option<StoredOperation>> {
        let mut connection = self.connection().await?;
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
                .context("incomplete graph issuance operation")
        };
        Ok(Some(StoredOperation {
            request_digest: required(b"request_digest")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid graph issuance request digest"))?,
            status_capability_digest: required(b"status_capability_digest")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid graph issuance capability digest"))?,
            issuance_policy_id: String::from_utf8(required(b"issuance_policy_id")?)?,
            graph_id: String::from_utf8(required(b"graph_id")?)?,
            keyset_id: String::from_utf8(required(b"keyset_id")?)?,
            descriptor_id: String::from_utf8(required(b"descriptor_id")?)?,
            signer_key_id: String::from_utf8(required(b"signer_key_id")?)?,
            quantity: String::from_utf8(required(b"quantity")?)?.parse()?,
            response: required(b"response")?,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn reserve(
        &self,
        operation_id: &[u8; 16],
        request_digest: &[u8; 32],
        status_capability: &[u8; 32],
        policy: &GraphIssuancePolicy,
        authorization_nullifier_digest: &[u8; 32],
        global_spend_key: Option<&str>,
        signer_key_id: &str,
        blind_signature: &[u8],
        response: &[u8],
        descriptor_valid_from: i64,
        descriptor_valid_until: i64,
    ) -> Result<ReserveOutcome> {
        let capability_digest = status_digest(status_capability);
        let policy_digest = policy_digest(policy);
        let authorization_key = format!(
            "{PREFIX}authorization:{}:{}",
            policy.issuance_policy_id,
            hex::encode(authorization_nullifier_digest)
        );
        let budget_key = format!("{PREFIX}budget:{}", policy.budget_id);
        let no_global_spend = Self::no_global_spend_key(operation_id);
        let mut connection = self.connection().await?;
        let code: i64 = redis::Script::new(RESERVE)
            .key(Self::operation_key(operation_id))
            .key(authorization_key)
            .key(budget_key)
            .key(global_spend_key.unwrap_or(&no_global_spend))
            .arg(request_digest.as_slice())
            .arg(capability_digest.as_slice())
            .arg(&policy.issuance_policy_id)
            .arg(&policy.graph_id)
            .arg(&policy.keyset_id)
            .arg(&policy.descriptor_id)
            .arg(signer_key_id)
            .arg(blind_signature)
            .arg(authorization_nullifier_digest.as_slice())
            .arg(policy_digest.as_slice())
            .arg(policy.quantity)
            .arg(policy.budget_limit)
            .arg(&policy.budget_id)
            .arg(response)
            .arg(global_spend_key.is_some())
            .arg(descriptor_valid_from)
            .arg(descriptor_valid_until)
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => ReserveOutcome::Created,
            1 => ReserveOutcome::Existing(Box::new(
                self.get(operation_id)
                    .await?
                    .context("existing graph issuance operation disappeared")?,
            )),
            2 | 3 => ReserveOutcome::Conflict,
            4 => ReserveOutcome::AuthorizationUsed,
            5 => ReserveOutcome::PolicyConflict,
            6 => ReserveOutcome::BudgetExhausted,
            7 => ReserveOutcome::DescriptorWindow,
            _ => bail!("invalid graph issuance reservation result"),
        })
    }
}
