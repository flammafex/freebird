//! Local-only experimental runner; TLS termination and production deployment
//! are deliberately not implemented here.
use freebird_crypto::privacy_pass::PublicKey;
use freebird_privacy_pass_service::{
    admission::AdmissionStore,
    control::{self, ControlListener},
    issuer::{self, Issuer},
    key_store::{KeyState, KeyStore},
    origin::{self, Origin, OriginKeyState},
};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const USAGE: &str = "\
Experimental Privacy Pass (one process per role; no failover or multi-instance).
Usage:
  freebird-privacy-pass-service init-issuer <issuer-state-dir>
  freebird-privacy-pass-service provision <issuer-state-dir>
  freebird-privacy-pass-service provision-live <issuer-state-dir>
  freebird-privacy-pass-service recover-issuer-admission <issuer-state-dir>
  freebird-privacy-pass-service stage-issuer-key <issuer-state-dir>
  freebird-privacy-pass-service export-issuer-spki <issuer-state-dir> <key-id-hex> <new-output-path>
  freebird-privacy-pass-service issuer-key-status <issuer-state-dir>
  freebird-privacy-pass-service activate-issuer-key <issuer-state-dir> <key-id-hex> <activation-unix-seconds>
  freebird-privacy-pass-service retire-issuer-key <issuer-state-dir> <key-id-hex>
  freebird-privacy-pass-service serve-issuer <issuer-state-dir> <issuer-name> <https-request-url> <loopback-bind>
  freebird-privacy-pass-service init-origin <origin-state-dir> <genesis-spki-der-path> <key-id-hex>
  freebird-privacy-pass-service install-origin-key <origin-state-dir> <spki-der-path> <key-id-hex> <activation-unix-seconds>
  freebird-privacy-pass-service origin-key-status <origin-state-dir>
  freebird-privacy-pass-service recover-origin-context <origin-state-dir>
  freebird-privacy-pass-service retire-origin-key <origin-state-dir> <key-id-hex>
  freebird-privacy-pass-service serve-origin <origin-state-dir> <issuer-name> <origin-name> <loopback-bind>
Listeners are loopback HTTP ONLY, not production TLS. The HTTPS request URL
describes an external endpoint; this runner does not provide TLS.
Offline key maintenance refuses while a process serves the same state: stop the
issuer or origin first. Activation is whole-hour Unix seconds in the future;
rotation order is ORIGIN FIRST (install-origin-key), then activate-issuer-key.
Retire the old Issuer key once now >= successor activation; retire the old
Origin key once now >= successor activation + 420 seconds.
Initialization requires a fresh directory;
partial failures are never reset automatically.";

const HOUR: u64 = 3600;
const KEY_V1: &str = "key schema v1 unsupported; no migration — initialize fresh state";
const ORIGIN_V1: &str = "origin schema v1 unsupported; no migration — initialize fresh state";
const INVALID_KEY_ID: &str = "invalid key ID (expected 64 hex digits)";
const INVALID_TIME: &str = "invalid activation time (expected decimal Unix seconds)";

type Result<T> = std::result::Result<T, &'static str>;

fn loopback_bind(value: &str) -> Result<SocketAddr> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "invalid bind address (expected a loopback IP:port)")?;
    if !address.ip().is_loopback() {
        return Err("non-loopback listeners are unsupported; no production TLS is provided");
    }
    Ok(address)
}

fn fresh_directory(path: &Path) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "cannot create fresh state directory (existing paths are never reset)")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| "cannot persist fresh state directory; partial state retained")
}

fn admission(dir: &Path) -> Result<AdmissionStore> {
    reject_legacy(dir)?;
    AdmissionStore::open(dir.join("admission.sqlite"), dir.join("generation"))
        .map_err(|_| "cannot open issuer state (missing, invalid, or already owned)")
}

fn reject_legacy(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir.join("signing.pk8")) {
        Ok(_) => Err(
            "unsupported experimental state: signing.pk8 exists; no migration or reset supported",
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("cannot inspect issuer state"),
    }
}

/// Only the two explicit schema refusals are surfaced verbatim; every other
/// failure keeps its generic, secret-free message.
fn surface(error: &anyhow::Error, generic: &'static str) -> &'static str {
    match error.to_string().as_str() {
        KEY_V1 => KEY_V1,
        ORIGIN_V1 => ORIGIN_V1,
        _ => generic,
    }
}

fn keys(dir: &Path) -> Result<KeyStore> {
    reject_legacy(dir)?;
    KeyStore::open(dir.join("issuer-keys.sqlite")).map_err(|error| {
        surface(
            &error,
            "cannot open issuer keys (missing, invalid, or already owned); stop issuer first",
        )
    })
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "invalid system clock")
}

fn parse_seconds(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(INVALID_TIME);
    }
    value.parse().map_err(|_| INVALID_TIME)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_key_id(value: &str) -> Result<[u8; 32]> {
    let digits = value.as_bytes();
    if digits.len() != 64 {
        return Err(INVALID_KEY_ID);
    }
    let mut id = [0; 32];
    for (index, slot) in id.iter_mut().enumerate() {
        let high = hex_digit(digits[index * 2]).ok_or(INVALID_KEY_ID)?;
        let low = hex_digit(digits[index * 2 + 1]).ok_or(INVALID_KEY_ID)?;
        *slot = high << 4 | low;
    }
    Ok(id)
}

fn public_id(id: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    id.iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}

/// Reads a canonical SPKI DER file whose SHA-256 is the operator-supplied ID.
/// Checked before any state directory is created.
fn read_checked_spki(path: &str, key_id: [u8; 32]) -> Result<Vec<u8>> {
    let spki = fs::read(path).map_err(|_| "cannot read public SPKI DER")?;
    let key = PublicKey::from_spki(&spki).map_err(|_| "public SPKI is not canonical")?;
    if key.to_spki() != spki.as_slice() || key.key_id() != key_id {
        return Err("key ID does not match the canonical public SPKI");
    }
    Ok(spki)
}

/// Creates a brand-new output file with mode 0600, never overwriting an existing path.
fn export_public(spki: &[u8], path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "cannot create export (output must not exist); inspect output before retry")?;
    file.write_all(spki)
        .and_then(|()| file.sync_all())
        .map_err(|_| "export failed; possibly partial output retained for operator inspection")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| "export persistence failed; output retained for operator inspection")
}

/// One printed key row. Times are Unix seconds, `None` renders as `-`.
struct StatusRow {
    state: &'static str,
    key_id: [u8; 32],
    activation: Option<u64>,
    issuance_end: Option<u64>,
    acceptance_deadline: Option<u64>,
}

fn seconds(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |v| v.to_string())
}

fn print_status(now: u64, high_water: u64, rows: &[StatusRow]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "now {now}")
        .and_then(|()| writeln!(stdout, "high-water {high_water}"))
        .and_then(|()| {
            rows.iter().try_for_each(|row| {
                writeln!(
                    stdout,
                    "{} {} {} {} {}",
                    row.state,
                    public_id(&row.key_id),
                    seconds(row.activation),
                    seconds(row.issuance_end),
                    seconds(row.acceptance_deadline),
                )
            })
        })
        .and_then(|()| stdout.flush())
        .map_err(|_| "key status output failed")
}

fn issuer_state(state: KeyState) -> &'static str {
    match state {
        KeyState::Staged => "staged",
        KeyState::Scheduled => "scheduled",
        KeyState::Active => "active",
        KeyState::RetiredForIssuance => "retired-for-issuance",
        KeyState::Retired => "retired",
    }
}

fn origin_state(state: OriginKeyState) -> &'static str {
    match state {
        OriginKeyState::Installed => "installed",
        OriginKeyState::Advertising => "advertising",
        OriginKeyState::Verifying => "verifying",
        OriginKeyState::Retired => "retired",
    }
}

fn issuer_key_status(dir: &Path) -> Result<()> {
    let store = keys(dir)?;
    let now = unix_now()?;
    let manifest = store
        .manifest(now)
        .map_err(|error| surface(&error, "cannot read issuer key status"))?;
    let mut rows = Vec::with_capacity(manifest.keys.len());
    for key in &manifest.keys {
        rows.push(StatusRow {
            state: issuer_state(key.state),
            key_id: key.key_id,
            activation: key
                .activation_hour
                .map(|hour| hour.checked_mul(HOUR).ok_or("key status out of range"))
                .transpose()?,
            issuance_end: key.issuance_end,
            acceptance_deadline: key.acceptance_deadline,
        });
    }
    print_status(manifest.now, manifest.high_water, &rows)
}

fn origin_key_status(dir: &Path) -> Result<()> {
    let now = unix_now()?;
    let status = Origin::status(dir.join("origin.sqlite"), now).map_err(|error| {
        surface(
            &error,
            "cannot read origin key status (missing, invalid, or already owned)",
        )
    })?;
    let mut rows = Vec::with_capacity(status.keys.len());
    for key in &status.keys {
        rows.push(StatusRow {
            state: origin_state(key.state),
            key_id: key.key_id,
            activation: Some(
                key.activation_hour
                    .checked_mul(HOUR)
                    .ok_or("key status out of range")?,
            ),
            issuance_end: key.issuance_end,
            acceptance_deadline: key.acceptance_deadline,
        });
    }
    print_status(status.now, status.high_water, &rows)
}

async fn serve(router: axum::Router, bind: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| "cannot bind loopback listener")?;
    eprintln!("Experimental loopback HTTP only; no TLS or production-readiness claim.");
    axum::serve(listener, router)
        .await
        .map_err(|_| "HTTP server failed")
}

async fn run(args: &[String]) -> Result<()> {
    match args {
        [command, dir] if command == "init-issuer" => {
            let dir = Path::new(dir);
            reject_legacy(dir)?;
            fresh_directory(dir)?;
            AdmissionStore::initialize(dir.join("admission.sqlite"), dir.join("generation"))
                .map_err(|_| "issuer initialization failed; partial state retained")?;
            Issuer::initialize_key(dir.join("issuer-keys.sqlite"))
                .map_err(|_| "signing key initialization failed; partial state retained")
        }
        [command, dir] if command == "stage-issuer-key" => {
            let now = unix_now()?;
            keys(Path::new(dir))?.stage(now).map(|_| ()).map_err(|error| {
                surface(
                    &error,
                    "key staging failed (existing staged or scheduled key, clock, or invalid state); no activation performed",
                )
            })
        }
        [command, dir, key_id, output] if command == "export-issuer-spki" => {
            let key_id = parse_key_id(key_id)?;
            let store = keys(Path::new(dir))?;
            let spki = store
                .spki(key_id)
                .map_err(|_| "unknown key ID or invalid issuer state")?;
            export_public(&spki, Path::new(output))
        }
        [command, dir] if command == "issuer-key-status" => issuer_key_status(Path::new(dir)),
        [command, dir, key_id] if command == "retire-issuer-key" => {
            let key_id = parse_key_id(key_id)?;
            let now = unix_now()?;
            keys(Path::new(dir))?.retire(key_id, now).map_err(|error| {
                surface(
                    &error,
                    "issuer key retirement refused (unknown, already retired, not superseded, or invalid state/clock); no change committed",
                )
            })
        }
        [command, dir, key_id, at] if command == "activate-issuer-key" => {
            let key_id = parse_key_id(key_id)?;
            let at = parse_seconds(at)?;
            let now = unix_now()?;
            let store = keys(Path::new(dir))?;
            let manifest = store
                .manifest(now)
                .map_err(|_| "cannot read issuer key status")?;
            let candidate = manifest
                .keys
                .iter()
                .find(|key| key.state == KeyState::Staged)
                .or_else(|| {
                    manifest
                        .keys
                        .iter()
                        .find(|key| key.state == KeyState::Scheduled)
                });
            if candidate.map(|key| key.key_id) != Some(key_id) {
                return Err("key ID does not match the staged or scheduled issuer candidate");
            }
            store
                .schedule_activation(at, now)
                .map(|_| ())
                .map_err(|error| {
                    surface(
                        &error,
                        "issuer key activation refused (state missing, already owned by a running issuer, or invalid time); no change committed",
                    )
                })
        }
        [command, dir, spki_path, key_id] if command == "init-origin" => {
            let key_id = parse_key_id(key_id)?;
            let spki = read_checked_spki(spki_path, key_id)?;
            let dir = Path::new(dir);
            fresh_directory(dir)?;
            Origin::initialize(
                dir.join("origin.sqlite"),
                dir.join("context"),
                &spki,
                key_id,
            )
            .map_err(|error| {
                surface(
                    &error,
                    "origin initialization failed; partial state retained",
                )
            })
        }
        [command, dir, spki_path, key_id, at] if command == "install-origin-key" => {
            let key_id = parse_key_id(key_id)?;
            let spki = read_checked_spki(spki_path, key_id)?;
            let at = parse_seconds(at)?;
            let now = unix_now()?;
            Origin::install_key(Path::new(dir).join("origin.sqlite"), &spki, key_id, at, now)
                .map_err(|error| {
                    surface(
                        &error,
                        "origin key installation refused (state missing, already owned by a running origin, or invalid key/time); no change committed",
                    )
                })
        }
        [command, dir] if command == "origin-key-status" => origin_key_status(Path::new(dir)),
        [command, dir] if command == "recover-origin-context" => {
            let now = unix_now()?;
            let dir = Path::new(dir);
            origin::invalidate_context_for_restore(
                dir.join("origin.sqlite"),
                dir.join("context"),
                now,
            )
            .map_err(|error| {
                surface(
                    &error,
                    "Origin recovery refused; keep both services stopped",
                )
            })
        }
        [command, dir, key_id] if command == "retire-origin-key" => {
            let key_id = parse_key_id(key_id)?;
            let now = unix_now()?;
            Origin::retire_key(Path::new(dir).join("origin.sqlite"), key_id, now)
                .map_err(|error| {
                    surface(
                        &error,
                        "origin key retirement refused (unknown, already retired, too early, already owned, or invalid state/clock); no change committed",
                    )
                })
        }
        [command, dir] if command == "provision" => {
            let store = admission(Path::new(dir))?;
            let now = i64::try_from(unix_now()?).map_err(|_| "invalid system clock")?;
            let invitation = store
                .provision(now)
                .map_err(|_| "invitation provisioning failed")?;
            // The invitation is intentionally emitted only here, never in errors
            // or diagnostics. A failed write does not undo durable provisioning.
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{invitation}")
                .and_then(|()| stdout.flush())
                .map_err(|_| "invitation output failed; no automatic retry")
        }
        [command, dir] if command == "provision-live" => {
            let invitation = control::provision_live(Path::new(dir)).await?;
            // As with offline provisioning, stdout is the sole intended output.
            // A failed output write does not undo the durable invitation.
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{invitation}")
                .and_then(|()| stdout.flush())
                .map_err(|_| control::LIVE_ERROR)
        }
        [command, dir] if command == "recover-issuer-admission" => admission(Path::new(dir))?
            .rotate_generation_for_restore()
            .map_err(|_| "admission recovery refused; keep both services stopped"),
        [command, dir, name, request_url, bind] if command == "serve-issuer" => {
            let bind = loopback_bind(bind)?;
            let uri: axum::http::Uri = request_url
                .parse()
                .map_err(|_| "invalid HTTPS request URL")?;
            if uri.scheme_str() != Some("https") {
                return Err(
                    "issuer request URL must use HTTPS (listener itself is local HTTP only)",
                );
            }
            let now = unix_now()?;
            let dir = Path::new(dir);
            let store = Arc::new(admission(dir)?);
            let issuer = Issuer::open(
                dir.join("issuer-keys.sqlite"),
                store.clone(),
                name.clone(),
                request_url.clone(),
                now,
            )
            .map_err(|error| {
                surface(
                    &error,
                    "cannot open issuer (invalid configuration, key, or state; or no active key)",
                )
            })?;
            let control =
                ControlListener::bind(dir).map_err(|_| "cannot bind issuer control socket")?;
            tokio::select! {
                result = serve(issuer::router(Arc::new(issuer)), bind) => result,
                result = control.serve(store) =>
                    result.map_err(|_| "issuer control server failed"),
            }
        }
        [command, dir, issuer_name, origin_name, bind] if command == "serve-origin" => {
            let bind = loopback_bind(bind)?;
            let dir = Path::new(dir);
            let db = dir.join("origin.sqlite");
            let now = unix_now()?;
            // Origin::open takes no clock, so refuse here: a clock behind the
            // durable high-water mark, or no advertising key, would only 503 later.
            let status = Origin::status(&db, now).map_err(|error| {
                surface(
                    &error,
                    "cannot open origin (invalid configuration/state or already owned)",
                )
            })?;
            if now < status.high_water {
                return Err("clock is behind the origin high-water mark");
            }
            if !status
                .keys
                .iter()
                .any(|key| key.state == OriginKeyState::Advertising)
            {
                return Err("no advertising origin key at this time (see origin-key-status)");
            }
            let origin = Origin::open(db, dir.join("context"), issuer_name, origin_name).map_err(
                |error| {
                    surface(
                        &error,
                        "cannot open origin (invalid configuration/state or already owned)",
                    )
                },
            )?;
            serve(origin::router(Arc::new(origin)), bind).await
        }
        _ => Err("invalid arguments"),
    }
}

#[tokio::main]
async fn main() {
    let args: std::result::Result<Vec<_>, _> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect();
    let result = match args {
        Ok(args) => run(&args).await,
        Err(_) => Err("invalid arguments"),
    };
    if let Err(message) = result {
        // Never display underlying errors, paths, key material, or arguments.
        eprintln!("{message}\n\n{USAGE}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{loopback_bind, parse_key_id, parse_seconds, public_id};

    #[test]
    fn only_numeric_loopback_listeners() {
        for value in ["127.0.0.1:8080", "127.1.2.3:0", "[::1]:8080"] {
            assert!(loopback_bind(value).is_ok());
        }
        for value in [
            "0.0.0.0:8080",
            "[::]:8080",
            "192.0.2.1:8080",
            "localhost:8080",
            "https://127.0.0.1:8080",
        ] {
            assert!(loopback_bind(value).is_err());
        }
    }

    #[test]
    fn key_id_hex_round_trips_and_rejects_malformed_input() {
        let id: [u8; 32] = core::array::from_fn(|i| i as u8 * 7);
        let text = public_id(&id);
        assert_eq!(text.len(), 64);
        assert_eq!(parse_key_id(&text).unwrap(), id);
        assert_eq!(parse_key_id(&text.to_uppercase()).unwrap(), id);
        let long = format!("{text}0");
        let bad_digit = text.replacen('0', "g", 1);
        for value in ["", &text[..63], long.as_str(), bad_digit.as_str()] {
            assert!(parse_key_id(value).is_err());
        }
    }

    #[test]
    fn activation_seconds_are_plain_decimal() {
        assert_eq!(parse_seconds("7200").unwrap(), 7200);
        for value in ["", "-1", "+1", "1e3", " 1", "0x10"] {
            assert!(parse_seconds(value).is_err());
        }
    }
}
