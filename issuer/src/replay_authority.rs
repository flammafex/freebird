// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable V4 replay-authority state, independent of graph issuance.

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::{
    api::{V4ReplayAuthorityDiscovery, V4_REPLAY_AUTHORITY_MAX_TOMBSTONES},
    replay_authority_api::{self, ReplayAuthorityProbeV1},
};
use rand::RngCore;
use std::collections::HashMap;

const AUTHORITY_ID_KEY: &str = "freebird:v4-replay-authority:v1:id";
const TOMBSTONES_KEY: &str = "freebird:v4-replay-authority:v1:scope-tombstones";
const PROBE_PREFIX: &str = "freebird:v4-replay-authority:v1:probe:";
const ACK_PREFIX: &str = "freebird:v4-replay-authority:v1:ack:";
const PROBE_TTL_SECS: u64 = 30;

const PROBE_SCRIPT: &str = r#"
local authority=redis.call('GET',KEYS[1])
if redis.call('TTL',KEYS[1])~=-1 or not authority or string.len(authority)~=32 or authority~=ARGV[1] then
  return {1,''}
end
local challenge=redis.call('GETDEL',KEYS[2])
if not challenge then return {2,''} end
return {0,challenge}
"#;

#[derive(Clone)]
pub struct ReplayAuthority {
    client: redis::Client,
}

impl ReplayAuthority {
    pub fn new(redis_url: &str) -> Result<Self> {
        Ok(Self {
            client: redis::Client::open(redis_url)?,
        })
    }

    async fn connection(&self) -> Result<redis::aio::Connection> {
        Ok(self.client.get_async_connection().await?)
    }

    pub async fn initialize(&self, scopes: &[[u8; 32]]) -> Result<()> {
        let mut connection = self.connection().await?;
        let authority_type: String = redis::cmd("TYPE")
            .arg(AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if authority_type != "none" && authority_type != "string" {
            bail!("replay authority identity has an invalid Redis type")
        }
        if authority_type == "string" {
            let ttl: i64 = redis::cmd("TTL")
                .arg(AUTHORITY_ID_KEY)
                .query_async(&mut connection)
                .await?;
            if ttl != -1 {
                bail!("replay authority identity must not expire")
            }
        } else {
            let mut authority = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut authority);
            let created: Option<String> = redis::cmd("SET")
                .arg(AUTHORITY_ID_KEY)
                .arg(authority.to_vec())
                .arg("NX")
                .query_async(&mut connection)
                .await?;
            if created.is_none() {
                let value: Vec<u8> = redis::cmd("GET")
                    .arg(AUTHORITY_ID_KEY)
                    .query_async(&mut connection)
                    .await?;
                if value.len() != 32 {
                    bail!("replay authority identity is not 32 bytes")
                }
            }
        }

        let tombstone_type: String = redis::cmd("TYPE")
            .arg(TOMBSTONES_KEY)
            .query_async(&mut connection)
            .await?;
        if tombstone_type != "none" && tombstone_type != "hash" {
            bail!("replay authority scope tombstones have an invalid Redis type")
        }
        if tombstone_type == "hash" {
            let ttl: i64 = redis::cmd("TTL")
                .arg(TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?;
            if ttl != -1 {
                bail!("replay authority scope tombstones must not expire")
            }
        }
        let existing: HashMap<Vec<u8>, Vec<u8>> = if tombstone_type == "hash" {
            redis::cmd("HGETALL")
                .arg(TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?
        } else {
            HashMap::new()
        };
        let mut retained = Vec::with_capacity(existing.len() + scopes.len());
        for (field, value) in existing {
            let text = String::from_utf8(field).context("invalid scope tombstone field")?;
            let raw: [u8; 32] = hex::decode(&text)
                .context("invalid scope tombstone encoding")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("scope tombstone is not 32 bytes"))?;
            if hex::encode(raw) != text || value.as_slice() != raw.as_slice() {
                bail!("invalid replay authority scope tombstone")
            }
            retained.push(raw);
        }
        retained.extend(scopes.iter().copied());
        retained.sort_unstable();
        retained.dedup();
        if retained.len() > V4_REPLAY_AUTHORITY_MAX_TOMBSTONES {
            bail!("too many replay authority scope tombstones")
        }
        for scope in retained {
            redis::cmd("HSET")
                .arg(TOMBSTONES_KEY)
                .arg(hex::encode(scope))
                .arg(scope.to_vec())
                .query_async::<_, i64>(&mut connection)
                .await?;
        }
        Ok(())
    }

    pub async fn read_state(&self) -> Result<([u8; 32], Vec<[u8; 32]>)> {
        let mut connection = self.connection().await?;
        let authority_type: String = redis::cmd("TYPE")
            .arg(AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if authority_type != "string" {
            bail!("replay authority identity is missing or has an invalid Redis type")
        }
        let ttl: i64 = redis::cmd("TTL")
            .arg(AUTHORITY_ID_KEY)
            .query_async(&mut connection)
            .await?;
        if ttl != -1 {
            bail!("replay authority identity must not expire")
        }
        let authority: [u8; 32] = redis::cmd("GET")
            .arg(AUTHORITY_ID_KEY)
            .query_async::<_, Vec<u8>>(&mut connection)
            .await?
            .try_into()
            .map_err(|_| anyhow::anyhow!("replay authority identity is not 32 bytes"))?;
        let tombstone_type: String = redis::cmd("TYPE")
            .arg(TOMBSTONES_KEY)
            .query_async(&mut connection)
            .await?;
        if tombstone_type != "none" && tombstone_type != "hash" {
            bail!("replay authority scope tombstones have an invalid Redis type")
        }
        if tombstone_type == "hash" {
            let ttl: i64 = redis::cmd("TTL")
                .arg(TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?;
            if ttl != -1 {
                bail!("replay authority scope tombstones must not expire")
            }
        }
        let existing: HashMap<Vec<u8>, Vec<u8>> = if tombstone_type == "hash" {
            redis::cmd("HGETALL")
                .arg(TOMBSTONES_KEY)
                .query_async(&mut connection)
                .await?
        } else {
            HashMap::new()
        };
        if existing.len() > V4_REPLAY_AUTHORITY_MAX_TOMBSTONES {
            bail!("too many replay authority scope tombstones")
        }
        let mut tombstones = Vec::with_capacity(existing.len());
        for (field, value) in existing {
            let text = String::from_utf8(field).context("invalid scope tombstone field")?;
            let scope: [u8; 32] = hex::decode(&text)
                .context("invalid scope tombstone encoding")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("scope tombstone is not 32 bytes"))?;
            if hex::encode(scope) != text || value.as_slice() != scope.as_slice() {
                bail!("invalid replay authority scope tombstone")
            }
            tombstones.push(scope);
        }
        tombstones.sort_unstable();
        Ok((authority, tombstones))
    }

    /// Check the durable identity and tombstone namespace without mutating it.
    pub async fn health_check(&self) -> Result<()> {
        self.read_state().await.map(|_| ())
    }

    pub async fn discovery(&self, issuer_id: String) -> Result<V4ReplayAuthorityDiscovery> {
        let (authority, tombstones) = self.read_state().await?;
        let discovery = V4ReplayAuthorityDiscovery {
            issuer_id,
            authority_id: Base64UrlUnpadded::encode_string(&authority),
            v4_scope_digest_tombstones: tombstones
                .iter()
                .map(|scope| Base64UrlUnpadded::encode_string(scope))
                .collect(),
        };
        discovery.validate().map_err(anyhow::Error::msg)?;
        Ok(discovery)
    }

    pub async fn probe(
        &self,
        probe: &ReplayAuthorityProbeV1,
        issuer_id: &str,
    ) -> Result<Option<[u8; 32]>> {
        let authority = probe.authority_id()?;
        let probe_id = probe.probe_id()?;
        let mut connection = self.connection().await?;
        let (code, challenge): (i64, Vec<u8>) = redis::Script::new(PROBE_SCRIPT)
            .key(AUTHORITY_ID_KEY)
            .key(format!("{PROBE_PREFIX}{}", hex::encode(probe_id)))
            .arg(authority.to_vec())
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
        let proof = replay_authority_api::replay_authority_proof_v1(
            &challenge, &authority, &probe_id, issuer_id,
        )?;
        let ack: Option<String> = redis::cmd("SET")
            .arg(format!("{ACK_PREFIX}{}", hex::encode(probe_id)))
            .arg(proof.to_vec())
            .arg("NX")
            .arg("EX")
            .arg(PROBE_TTL_SECS)
            .query_async(&mut connection)
            .await?;
        if ack.is_none() {
            bail!("replay authority acknowledgement already exists")
        }
        Ok(Some(proof))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn redis_url() -> Option<String> {
        std::env::var("FREEBIRD_REPLAY_TEST_REDIS_URL").ok()
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn durable_identity_tombstones_and_probe_ack_require_redis() -> Result<()> {
        let Some(url) = redis_url().await else {
            return Ok(());
        };
        let authority = ReplayAuthority::new(&url)?;
        let mut connection = authority.connection().await?;
        redis::cmd("FLUSHDB")
            .query_async::<_, ()>(&mut connection)
            .await?;
        drop(connection);

        let scope = [7u8; 32];
        authority.initialize(&[scope]).await?;
        let (identity, tombstones) = authority.read_state().await?;
        assert_eq!(identity.len(), 32);
        assert_eq!(tombstones, vec![scope]);

        let ttl: i64 = redis::cmd("TTL")
            .arg(TOMBSTONES_KEY)
            .query_async(&mut authority.connection().await?)
            .await?;
        assert_eq!(ttl, -1);

        let probe_id = [8u8; 32];
        let challenge = [9u8; 32];
        let probe_key = format!("{PROBE_PREFIX}{}", hex::encode(probe_id));
        let mut connection = authority.connection().await?;
        redis::cmd("SET")
            .arg(&probe_key)
            .arg(challenge.to_vec())
            .arg("EX")
            .arg(PROBE_TTL_SECS)
            .query_async::<_, ()>(&mut connection)
            .await?;
        let identity_b64 = Base64UrlUnpadded::encode_string(&identity);
        let probe = ReplayAuthorityProbeV1 {
            version: replay_authority_api::REPLAY_AUTHORITY_VERSION_V1,
            authority_id: identity_b64,
            probe_id: Base64UrlUnpadded::encode_string(&probe_id),
        };
        let proof = authority.probe(&probe, "issuer:test").await?.unwrap();
        let ack_ttl: i64 = redis::cmd("TTL")
            .arg(format!("{ACK_PREFIX}{}", hex::encode(probe_id)))
            .query_async(&mut connection)
            .await?;
        assert!(ack_ttl > 0 && ack_ttl <= PROBE_TTL_SECS as i64);
        assert!(authority.probe(&probe, "issuer:test").await?.is_none());
        assert_eq!(proof.len(), 32);
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn expired_durable_tombstone_namespace_fails_closed() -> Result<()> {
        let Some(url) = redis_url().await else {
            return Ok(());
        };
        let authority = ReplayAuthority::new(&url)?;
        let mut connection = authority.connection().await?;
        redis::cmd("FLUSHDB")
            .query_async::<_, ()>(&mut connection)
            .await?;
        drop(connection);
        authority.initialize(&[[3u8; 32]]).await?;
        let mut connection = authority.connection().await?;
        redis::cmd("EXPIRE")
            .arg(TOMBSTONES_KEY)
            .arg(30)
            .query_async::<_, ()>(&mut connection)
            .await?;
        assert!(authority.read_state().await.is_err());
        assert!(authority.health_check().await.is_err());
        Ok(())
    }
}
