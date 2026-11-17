//! Local-only experimental runner; TLS termination and production deployment
//! are deliberately not implemented here.
use freebird_privacy_pass_service::{
    admission::AdmissionStore,
    issuer::{self, Issuer},
    key_store::KeyStore,
    origin::{self, Origin},
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
Experimental Privacy Pass (one process per role; no rotation or failover).
Usage:
  freebird-privacy-pass-service init-issuer <state-dir>
  freebird-privacy-pass-service init-origin <state-dir>
  freebird-privacy-pass-service provision <issuer-state-dir>
  freebird-privacy-pass-service stage-issuer-key <issuer-state-dir>
  freebird-privacy-pass-service export-staged-spki <issuer-state-dir> <new-output-path>
  freebird-privacy-pass-service issuer-key-status <issuer-state-dir>
  freebird-privacy-pass-service serve-issuer <issuer-state-dir> <issuer-name> <https-request-url> <loopback-bind>
  freebird-privacy-pass-service serve-origin <origin-state-dir> <issuer-name> <origin-name> <public-spki-der-path> <loopback-bind>
Listeners are loopback HTTP ONLY, not production TLS. The HTTPS request URL
describes an external endpoint; this runner does not provide TLS.
Stop the issuer before provisioning or key maintenance. Staging is not activation.
Initialization requires a fresh directory;
partial failures are never reset automatically.";

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

fn keys(dir: &Path) -> Result<KeyStore> {
    reject_legacy(dir)?;
    KeyStore::open(dir.join("issuer-keys.sqlite")).map_err(|_| {
        "cannot open issuer keys (missing, invalid, or already owned); stop issuer first"
    })
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

fn export_staged(store: &KeyStore, path: &Path) -> Result<()> {
    let spki = store
        .staged_spki()
        .map_err(|_| "cannot read staged public key")?
        .ok_or("no staged public key")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "cannot create export (output must not exist); inspect output before retry")?;
    file.write_all(&spki)
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
            keys(Path::new(dir))?.stage().map(|_| ()).map_err(|_| {
                "key staging failed (existing staged key or invalid state); no activation performed"
            })
        }
        [command, dir, output] if command == "export-staged-spki" => {
            let store = keys(Path::new(dir))?;
            export_staged(&store, Path::new(output))
        }
        [command, dir] if command == "issuer-key-status" => {
            let store = keys(Path::new(dir))?;
            let status = store
                .status()
                .map_err(|_| "cannot read issuer key status")?;
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "active {}", public_id(&status.active_key_id))
                .and_then(|()| match status.staged_key_id {
                    Some(id) => writeln!(stdout, "staged {}", public_id(&id)),
                    None => Ok(()),
                })
                .and_then(|()| stdout.flush())
                .map_err(|_| "key status output failed")
        }
        [command, dir] if command == "init-origin" => {
            let dir = Path::new(dir);
            fresh_directory(dir)?;
            Origin::initialize(dir.join("origin.sqlite"), dir.join("context"))
                .map_err(|_| "origin initialization failed; partial state retained")
        }
        [command, dir] if command == "provision" => {
            let store = admission(Path::new(dir))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|duration| i64::try_from(duration.as_secs()).ok())
                .ok_or("invalid system clock")?;
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
            let dir = Path::new(dir);
            let store = Arc::new(admission(dir)?);
            let issuer = Issuer::open(
                dir.join("issuer-keys.sqlite"),
                store,
                name.clone(),
                request_url.clone(),
            )
            .map_err(|_| "cannot open issuer (invalid configuration, key, or state)")?;
            serve(issuer::router(Arc::new(issuer)), bind).await
        }
        [command, dir, issuer_name, origin_name, public_spki_path, bind]
            if command == "serve-origin" =>
        {
            let bind = loopback_bind(bind)?;
            let public_spki =
                fs::read(public_spki_path).map_err(|_| "cannot read public SPKI DER")?;
            let dir = Path::new(dir);
            let origin = Origin::open(
                dir.join("origin.sqlite"),
                dir.join("context"),
                issuer_name,
                origin_name,
                &public_spki,
            )
            .map_err(|_| "cannot open origin (invalid configuration/state or already owned)")?;
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
    use super::loopback_bind;

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
}
