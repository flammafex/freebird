// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable, binary-safe Redis authority for private bearer exchange.

use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::collections::{HashMap, HashSet};

const PREFIX: &str = "freebird:exchange:v1:";
pub const LEASE_SECS: u64 = 30;

// KEYS: op, source spends..., target refs..., receipt ref, capacity keys...
// ARGV 1..13 are fixed, followed by source windows, target windows, and
// capacity amount/limit pairs. Every check precedes the first mutation.
const RESERVE: &str = r#"
local op=KEYS[1]
if redis.call('EXISTS',op)==1 then
  if redis.call('HGET',op,'request_hash')==ARGV[1] then return 1 else return 2 end
end
local now=tonumber(redis.call('TIME')[1])
local ns=tonumber(ARGV[11]); local nt=tonumber(ARGV[12]); local nc=tonumber(ARGV[13])
local p=14; local seen={}
for i=1,ns do
  local first=tonumber(ARGV[p]); local last=tonumber(ARGV[p+1]); p=p+2
  local k=KEYS[1+i]
  if seen[k] then return 3 end; seen[k]=true
  if now<first or now>last then return 4 end
  if redis.call('EXISTS',k)==1 then return 5 end
end
local target_seen={}
for i=1,nt do
  local first=tonumber(ARGV[p]); local last=tonumber(ARGV[p+1]); p=p+2
  local k=KEYS[1+ns+i]
  if target_seen[k] then return 6 end; target_seen[k]=true
  if now<first or now>last then return 7 end
end
local cap_seen={}
for i=1,nc do
  local amount=tonumber(ARGV[p]); local limit=tonumber(ARGV[p+1]); p=p+2
  local k=KEYS[2+ns+nt+i]
  if cap_seen[k] or amount<1 or limit<1 then return 8 end; cap_seen[k]=true
  if tonumber(redis.call('GET',k) or '0')+amount>limit then return 9 end
end
p=14
for i=1,ns do
  local last=tonumber(ARGV[p+1]); p=p+2
  if redis.call('SET',KEYS[1+i],ARGV[1],'NX','EXAT',last+1)==false then return 5 end
end
for i=1,nt do p=p+2; redis.call('INCR',KEYS[1+ns+i]) end
redis.call('INCR',KEYS[2+ns+nt])
for i=1,nc do
  local amount=tonumber(ARGV[p]); p=p+2
  redis.call('INCRBY',KEYS[2+ns+nt+i],amount)
end
redis.call('HSET',op,
 'request_hash',ARGV[1], 'profile_id',ARGV[2], 'rule_id',ARGV[3],
 'target_keyset_id',ARGV[4], 'receipt_key_id',ARGV[5],
 'sources',ARGV[6], 'outputs',ARGV[7], 'capacities',ARGV[8],
 'target_refs',ARGV[9], 'receipt_ref',KEYS[2+ns+nt],
 'state','1', 'fence',ARGV[10], 'lease_until',now+tonumber(ARGV[14+2*ns+2*nt+2*nc]),
 'created_at',now, 'receipt_expires_at',now+tonumber(ARGV[15+2*ns+2*nt+2*nc]))
return 0
"#;

const CLAIM: &str = r#"
local s=redis.call('HGET',KEYS[1],'state'); if not s then return 3 end
if s=='3' then return 4 end
if s~='1' and s~='2' then return 5 end
local now=tonumber(redis.call('TIME')[1])
if tonumber(redis.call('HGET',KEYS[1],'lease_until'))>now then return 1 end
redis.call('HSET',KEYS[1],'fence',ARGV[1],'lease_until',now+tonumber(ARGV[2]))
return 0
"#;

const RESULT: &str = r#"
local s=redis.call('HGET',KEYS[1],'state'); if not s then return 3 end
if s=='2' or s=='3' then
 if redis.call('HGET',KEYS[1],'result')==ARGV[2] and redis.call('HGET',KEYS[1],'result_digest')==ARGV[3] then return 1 else return 2 end
end
if s~='1' then return 3 end
if redis.call('HGET',KEYS[1],'fence')~=ARGV[1] then return 4 end
local refs=ARGV[4]; local p=1
while p<=string.len(refs) do
 local n=string.byte(refs,p)*16777216+string.byte(refs,p+1)*65536+string.byte(refs,p+2)*256+string.byte(refs,p+3); p=p+4
 local k=string.sub(refs,p,p+n-1); p=p+n
 if tonumber(redis.call('GET',k) or '0')<1 then return 5 end
end
p=1
while p<=string.len(refs) do
 local n=string.byte(refs,p)*16777216+string.byte(refs,p+1)*65536+string.byte(refs,p+2)*256+string.byte(refs,p+3); p=p+4
 local k=string.sub(refs,p,p+n-1); p=p+n; redis.call('DECR',k)
end
redis.call('HSET',KEYS[1],'state','2','result',ARGV[2],'result_digest',ARGV[3])
return 0
"#;

const COMMIT: &str = r#"
local s=redis.call('HGET',KEYS[1],'state'); if not s then return 3 end
if s=='3' then
 if redis.call('HGET',KEYS[1],'receipt')==ARGV[2] and redis.call('HGET',KEYS[1],'response')==ARGV[3] then return 1 else return 2 end
end
if s~='2' then return 3 end
if redis.call('HGET',KEYS[1],'fence')~=ARGV[1] then return 4 end
local k=redis.call('HGET',KEYS[1],'receipt_ref')
if tonumber(redis.call('GET',k) or '0')<1 then return 5 end
redis.call('DECR',k)
redis.call('HSET',KEYS[1],'state','3','receipt',ARGV[2],'response',ARGV[3])
return 0
"#;

#[derive(Clone)]
pub struct ExchangeStore {
    client: redis::Client,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Reserved,
    ResultReady,
    Committed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceWork {
    pub descriptor_id: String,
    pub spend_key: String,
    pub valid_from: i64,
    pub valid_until: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputWork {
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
    pub quantity: u32,
    pub blinded_value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapacityEntry {
    pub key: String,
    pub amount: u64,
    pub limit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetRef {
    pub descriptor_id: String,
    pub key: String,
    pub valid_from: i64,
    pub valid_until: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRecord {
    pub request_hash: [u8; 32],
    pub state: State,
    pub fence: Vec<u8>,
    pub lease_until: u64,
    pub created_at: u64,
    pub receipt_expires_at: u64,
    pub profile_id: String,
    pub rule_id: String,
    pub target_keyset_id: String,
    pub receipt_key_id: String,
    pub sources: Vec<SourceWork>,
    pub outputs: Vec<OutputWork>,
    pub capacities: Vec<CapacityEntry>,
    pub target_refs: Vec<TargetRef>,
    pub receipt_ref: String,
    pub result: Option<Vec<u8>>,
    pub result_digest: Option<[u8; 32]>,
    pub receipt: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}
pub type WorkRecord = OperationRecord;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub fence: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReserveOutcome {
    Created(Reservation),
    Existing(Box<OperationRecord>),
    Conflict,
    DuplicateSource,
    Spent,
    SourceWindow,
    TargetWindow,
    InvalidEntries,
    Capacity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Claimed(Reservation),
    Live,
    Committed,
    Missing,
    InvalidState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionOutcome {
    Applied,
    Repeated,
    StaleFence,
    Conflict,
    InvalidState,
    Underflow,
}

pub struct ReservationInput<'a> {
    pub operation_id: &'a [u8; 16],
    pub request_hash: &'a [u8; 32],
    pub profile_id: &'a str,
    pub rule_id: &'a str,
    pub target_keyset_id: &'a str,
    pub receipt_key_id: &'a str,
    pub sources: &'a [SourceWork],
    pub outputs: &'a [OutputWork],
    pub target_refs: &'a [TargetRef],
    pub receipt_ref_key: &'a str,
    pub capacities: &'a [CapacityEntry],
    pub receipt_lifetime_secs: u64,
}

impl ExchangeStore {
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self {
            client: redis::Client::open(url)?,
        })
    }

    async fn conn(&self) -> Result<redis::aio::Connection> {
        Ok(self.client.get_async_connection().await?)
    }

    pub async fn validate_durable_standalone(&self) -> Result<()> {
        let mut connection = self.conn().await?;
        let pong: String = redis::cmd("PING").query_async(&mut connection).await?;
        if pong != "PONG" {
            bail!("exchange Redis ping failed")
        }
        let info: String = redis::cmd("INFO")
            .arg("server")
            .query_async(&mut connection)
            .await?;
        let replication: String = redis::cmd("INFO")
            .arg("replication")
            .query_async(&mut connection)
            .await?;
        async fn config(connection: &mut redis::aio::Connection, name: &str) -> Result<String> {
            let values: Vec<String> = redis::cmd("CONFIG")
                .arg("GET")
                .arg(name)
                .query_async(connection)
                .await?;
            values
                .get(1)
                .cloned()
                .context("missing Redis configuration")
        }
        if config(&mut connection, "appendonly").await? != "yes"
            || config(&mut connection, "appendfsync").await? != "always"
            || config(&mut connection, "maxmemory-policy").await? != "noeviction"
        {
            bail!("exchange Redis durability policy is unsafe")
        }
        let persistence: String = redis::cmd("INFO")
            .arg("persistence")
            .query_async(&mut connection)
            .await?;
        validate_redis_info(&info, &replication, &persistence)?;
        Ok(())
    }

    pub(crate) fn op(id: &[u8; 16]) -> String {
        format!("{PREFIX}op:{}", hex::encode(id))
    }

    fn fence() -> Vec<u8> {
        let mut fence = vec![0; 32];
        OsRng.fill_bytes(&mut fence);
        fence
    }

    pub async fn reserve(&self, input: ReservationInput<'_>) -> Result<ReserveOutcome> {
        if let Some(existing) = self.get(input.operation_id).await? {
            return Ok(if existing.request_hash == *input.request_hash {
                ReserveOutcome::Existing(Box::new(existing))
            } else {
                ReserveOutcome::Conflict
            });
        }
        if input.sources.is_empty() || input.outputs.is_empty() || input.receipt_lifetime_secs == 0
        {
            bail!("invalid reservation bounds")
        }
        unique(input.sources.iter().map(|s| s.spend_key.as_str()), "source")?;
        unique(
            input.target_refs.iter().map(|r| r.key.as_str()),
            "target ref",
        )?;
        unique(input.capacities.iter().map(|c| c.key.as_str()), "capacity")?;
        if input
            .capacities
            .iter()
            .any(|c| c.amount == 0 || c.limit == 0)
        {
            bail!("invalid capacity entry")
        }

        let source_bytes = encode_sources(input.sources)?;
        let output_bytes = encode_outputs(input.outputs)?;
        let capacity_bytes = encode_capacities(input.capacities)?;
        let target_ref_bytes = encode_target_refs(input.target_refs)?;
        let fence = Self::fence();
        let script = redis::Script::new(RESERVE);
        script.key(Self::op(input.operation_id));
        for source in input.sources {
            script.key(&source.spend_key);
        }
        for target in input.target_refs {
            script.key(&target.key);
        }
        script.key(input.receipt_ref_key);
        for capacity in input.capacities {
            script.key(&capacity.key);
        }
        script
            .arg(input.request_hash.as_slice())
            .arg(input.profile_id)
            .arg(input.rule_id)
            .arg(input.target_keyset_id)
            .arg(input.receipt_key_id)
            .arg(source_bytes)
            .arg(output_bytes)
            .arg(capacity_bytes)
            .arg(target_ref_bytes)
            .arg(&fence)
            .arg(input.sources.len())
            .arg(input.target_refs.len())
            .arg(input.capacities.len());
        for source in input.sources {
            script.arg(source.valid_from).arg(source.valid_until);
        }
        for target in input.target_refs {
            script.arg(target.valid_from).arg(target.valid_until);
        }
        for capacity in input.capacities {
            script.arg(capacity.amount).arg(capacity.limit);
        }
        script.arg(LEASE_SECS).arg(input.receipt_lifetime_secs);
        let mut connection = self.conn().await?;
        let code: i64 = script.invoke_async(&mut connection).await?;
        Ok(match code {
            0 => ReserveOutcome::Created(Reservation { fence }),
            1 => ReserveOutcome::Existing(Box::new(
                self.get(input.operation_id)
                    .await?
                    .context("existing operation disappeared")?,
            )),
            2 => ReserveOutcome::Conflict,
            3 => ReserveOutcome::DuplicateSource,
            4 => ReserveOutcome::SourceWindow,
            5 => ReserveOutcome::Spent,
            6 | 8 => ReserveOutcome::InvalidEntries,
            7 => ReserveOutcome::TargetWindow,
            9 => ReserveOutcome::Capacity,
            _ => bail!("invalid reserve result"),
        })
    }

    pub async fn claim(&self, id: &[u8; 16]) -> Result<ClaimOutcome> {
        let fence = Self::fence();
        let mut connection = self.conn().await?;
        let code: i64 = redis::Script::new(CLAIM)
            .key(Self::op(id))
            .arg(&fence)
            .arg(LEASE_SECS)
            .invoke_async(&mut connection)
            .await?;
        Ok(match code {
            0 => ClaimOutcome::Claimed(Reservation { fence }),
            1 => ClaimOutcome::Live,
            3 => ClaimOutcome::Missing,
            4 => ClaimOutcome::Committed,
            5 => ClaimOutcome::InvalidState,
            _ => bail!("invalid claim result"),
        })
    }

    pub async fn result_ready(
        &self,
        id: &[u8; 16],
        fence: &[u8],
        result: &[u8],
        digest: &[u8; 32],
    ) -> Result<TransitionOutcome> {
        let record = self.get(id).await?.context("missing operation")?;
        self.transition(
            RESULT,
            id,
            &[
                fence,
                result,
                digest,
                &encode_strings(record.target_refs.iter().map(|r| r.key.as_str()))?,
            ],
        )
        .await
    }

    pub async fn commit(
        &self,
        id: &[u8; 16],
        fence: &[u8],
        receipt: &[u8],
        response: &[u8],
    ) -> Result<TransitionOutcome> {
        self.transition(COMMIT, id, &[fence, receipt, response])
            .await
    }

    async fn transition(
        &self,
        lua: &str,
        id: &[u8; 16],
        args: &[&[u8]],
    ) -> Result<TransitionOutcome> {
        let mut connection = self.conn().await?;
        let script = redis::Script::new(lua);
        script.key(Self::op(id));
        for arg in args {
            script.arg(*arg);
        }
        let code: i64 = script.invoke_async(&mut connection).await?;
        Ok(match code {
            0 => TransitionOutcome::Applied,
            1 => TransitionOutcome::Repeated,
            2 => TransitionOutcome::Conflict,
            3 => TransitionOutcome::InvalidState,
            4 => TransitionOutcome::StaleFence,
            5 => TransitionOutcome::Underflow,
            _ => bail!("invalid transition result"),
        })
    }

    pub async fn get(&self, id: &[u8; 16]) -> Result<Option<OperationRecord>> {
        let mut connection = self.conn().await?;
        let values: HashMap<Vec<u8>, Vec<u8>> = redis::cmd("HGETALL")
            .arg(Self::op(id))
            .query_async(&mut connection)
            .await?;
        if values.is_empty() {
            return Ok(None);
        }
        let required = |name: &[u8]| {
            values
                .get(name)
                .cloned()
                .context("incomplete operation record")
        };
        let text = |name: &[u8]| -> Result<String> {
            String::from_utf8(required(name)?).context("invalid operation text")
        };
        let number = |name: &[u8]| -> Result<u64> { Ok(text(name)?.parse()?) };
        let state = match required(b"state")?.as_slice() {
            b"1" => State::Reserved,
            b"2" => State::ResultReady,
            b"3" => State::Committed,
            _ => bail!("invalid operation state"),
        };
        let request_hash = required(b"request_hash")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid request hash"))?;
        let result_digest = values
            .get(b"result_digest".as_slice())
            .map(|v| {
                v.clone()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid result digest"))
            })
            .transpose()?;
        Ok(Some(OperationRecord {
            request_hash,
            state,
            fence: required(b"fence")?,
            lease_until: number(b"lease_until")?,
            created_at: number(b"created_at")?,
            receipt_expires_at: number(b"receipt_expires_at")?,
            profile_id: text(b"profile_id")?,
            rule_id: text(b"rule_id")?,
            target_keyset_id: text(b"target_keyset_id")?,
            receipt_key_id: text(b"receipt_key_id")?,
            sources: decode_sources(&required(b"sources")?)?,
            outputs: decode_outputs(&required(b"outputs")?)?,
            capacities: decode_capacities(&required(b"capacities")?)?,
            target_refs: decode_target_refs(&required(b"target_refs")?)?,
            receipt_ref: text(b"receipt_ref")?,
            result: values.get(b"result".as_slice()).cloned(),
            result_digest,
            receipt: values.get(b"receipt".as_slice()).cloned(),
            response: values.get(b"response".as_slice()).cloned(),
        }))
    }

    /// Enumerate durable pending work for startup/readiness signer retention
    /// checks. The supported topology is standalone Redis, so SCAN is complete
    /// for the selected database without cross-shard ambiguity.
    pub async fn pending_records(&self) -> Result<Vec<OperationRecord>> {
        let mut connection = self.conn().await?;
        let mut cursor = 0u64;
        let mut ids = Vec::new();
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{PREFIX}op:*"))
                .arg("COUNT")
                .arg(128)
                .query_async(&mut connection)
                .await?;
            for key in keys {
                let encoded = key
                    .strip_prefix(&format!("{PREFIX}op:"))
                    .context("invalid operation index key")?;
                let id: [u8; 16] = hex::decode(encoded)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid operation index id"))?;
                ids.push(id);
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        drop(connection);
        let mut records = Vec::new();
        for id in ids {
            if let Some(record) = self.get(&id).await? {
                if record.state != State::Committed {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    #[cfg(test)]
    pub async fn redis_time(&self) -> Result<u64> {
        let mut c = self.conn().await?;
        let (seconds, _): (u64, u64) = redis::cmd("TIME").query_async(&mut c).await?;
        Ok(seconds)
    }

    #[cfg(test)]
    pub async fn raw_command<T: redis::FromRedisValue>(
        &self,
        command: &str,
        args: &[&[u8]],
    ) -> Result<T> {
        let mut c = self.conn().await?;
        let mut cmd = redis::cmd(command);
        for arg in args {
            cmd.arg(*arg);
        }
        Ok(cmd.query_async(&mut c).await?)
    }
}

fn info_value<'a>(info: &'a str, key: &str) -> Option<&'a str> {
    info.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find_map(|(name, value)| (name == key).then_some(value))
}

pub(super) fn validate_redis_info(
    server: &str,
    replication: &str,
    persistence: &str,
) -> Result<()> {
    if info_value(server, "redis_mode") != Some("standalone") {
        bail!("exchange requires standalone Redis")
    }
    if info_value(replication, "role") != Some("master") {
        bail!("exchange requires the authoritative Redis master")
    }
    if info_value(persistence, "aof_enabled") != Some("1") {
        bail!("exchange Redis AOF persistence is not active")
    }
    if info_value(persistence, "aof_last_write_status") != Some("ok") {
        bail!("exchange Redis reports an unhealthy AOF write status")
    }
    Ok(())
}

/// Target ref keys carry the immutable window after a separator. Redis counters
/// use only the prefix before `|`; callers create them with this helper.
pub fn target_ref_key(descriptor_id: &str, valid_from: i64, valid_until: i64) -> TargetRef {
    TargetRef {
        descriptor_id: descriptor_id.to_owned(),
        key: format!("{PREFIX}target-ref:{descriptor_id}"),
        valid_from,
        valid_until,
    }
}

pub fn receipt_ref_key(receipt_key_id: &str) -> String {
    format!("{PREFIX}receipt-ref:{receipt_key_id}")
}
pub fn capacity_key(descriptor_id: &str) -> String {
    format!("{PREFIX}capacity:{descriptor_id}")
}

fn unique<'a>(items: impl Iterator<Item = &'a str>, what: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for item in items {
        if !seen.insert(item) {
            bail!("duplicate {what}")
        }
    }
    Ok(())
}

fn put(bytes: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .context("record field too large")?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value);
    Ok(())
}
fn take<'a>(bytes: &'a [u8], position: &mut usize) -> Result<&'a [u8]> {
    let length = u32::from_be_bytes(
        bytes
            .get(*position..*position + 4)
            .context("truncated record")?
            .try_into()?,
    ) as usize;
    *position += 4;
    let value = bytes
        .get(*position..*position + length)
        .context("truncated record")?;
    *position += length;
    Ok(value)
}
fn text(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).context("invalid record UTF-8")
}
fn encode_strings<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for v in values {
        put(&mut out, v.as_bytes())?;
    }
    Ok(out)
}
fn encode_target_refs(values: &[TargetRef]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for v in values {
        put(&mut out, v.descriptor_id.as_bytes())?;
        put(&mut out, v.key.as_bytes())?;
        out.extend_from_slice(&v.valid_from.to_be_bytes());
        out.extend_from_slice(&v.valid_until.to_be_bytes());
    }
    Ok(out)
}
fn decode_target_refs(bytes: &[u8]) -> Result<Vec<TargetRef>> {
    let mut p = 0;
    let mut out = Vec::new();
    while p < bytes.len() {
        let descriptor_id = text(take(bytes, &mut p)?)?;
        let key = text(take(bytes, &mut p)?)?;
        let valid_from = i64::from_be_bytes(
            bytes
                .get(p..p + 8)
                .context("truncated target ref")?
                .try_into()?,
        );
        p += 8;
        let valid_until = i64::from_be_bytes(
            bytes
                .get(p..p + 8)
                .context("truncated target ref")?
                .try_into()?,
        );
        p += 8;
        out.push(TargetRef {
            descriptor_id,
            key,
            valid_from,
            valid_until,
        });
    }
    Ok(out)
}
fn encode_sources(values: &[SourceWork]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for v in values {
        put(&mut out, v.descriptor_id.as_bytes())?;
        put(&mut out, v.spend_key.as_bytes())?;
        out.extend_from_slice(&v.valid_from.to_be_bytes());
        out.extend_from_slice(&v.valid_until.to_be_bytes());
    }
    Ok(out)
}
fn decode_sources(bytes: &[u8]) -> Result<Vec<SourceWork>> {
    let mut p = 0;
    let mut out = Vec::new();
    while p < bytes.len() {
        let descriptor_id = text(take(bytes, &mut p)?)?;
        let spend_key = text(take(bytes, &mut p)?)?;
        let valid_from = i64::from_be_bytes(
            bytes
                .get(p..p + 8)
                .context("truncated source")?
                .try_into()?,
        );
        p += 8;
        let valid_until = i64::from_be_bytes(
            bytes
                .get(p..p + 8)
                .context("truncated source")?
                .try_into()?,
        );
        p += 8;
        out.push(SourceWork {
            descriptor_id,
            spend_key,
            valid_from,
            valid_until,
        });
    }
    Ok(out)
}
fn encode_outputs(values: &[OutputWork]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for v in values {
        put(&mut out, v.descriptor_id.as_bytes())?;
        put(&mut out, v.keyset_id.as_bytes())?;
        put(&mut out, v.slot_id.as_bytes())?;
        out.extend_from_slice(&v.quantity.to_be_bytes());
        put(&mut out, &v.blinded_value)?;
    }
    Ok(out)
}
fn decode_outputs(bytes: &[u8]) -> Result<Vec<OutputWork>> {
    let mut p = 0;
    let mut out = Vec::new();
    while p < bytes.len() {
        let descriptor_id = text(take(bytes, &mut p)?)?;
        let keyset_id = text(take(bytes, &mut p)?)?;
        let slot_id = text(take(bytes, &mut p)?)?;
        let quantity = u32::from_be_bytes(
            bytes
                .get(p..p + 4)
                .context("truncated output")?
                .try_into()?,
        );
        p += 4;
        let blinded_value = take(bytes, &mut p)?.to_vec();
        out.push(OutputWork {
            descriptor_id,
            keyset_id,
            slot_id,
            quantity,
            blinded_value,
        });
    }
    Ok(out)
}
fn encode_capacities(values: &[CapacityEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for v in values {
        put(&mut out, v.key.as_bytes())?;
        out.extend_from_slice(&v.amount.to_be_bytes());
        out.extend_from_slice(&v.limit.to_be_bytes());
    }
    Ok(out)
}
fn decode_capacities(bytes: &[u8]) -> Result<Vec<CapacityEntry>> {
    let mut p = 0;
    let mut out = Vec::new();
    while p < bytes.len() {
        let key = text(take(bytes, &mut p)?)?;
        let amount = u64::from_be_bytes(
            bytes
                .get(p..p + 8)
                .context("truncated capacity")?
                .try_into()?,
        );
        p += 8;
        let limit = u64::from_be_bytes(
            bytes
                .get(p..p + 8)
                .context("truncated capacity")?
                .try_into()?,
        );
        p += 8;
        out.push(CapacityEntry { key, amount, limit });
    }
    Ok(out)
}
