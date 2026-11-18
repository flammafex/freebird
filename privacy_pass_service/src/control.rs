//! Operators use the issuer's local socket to provision invitations and manage application admission.
//! A request that does not match the single-line format gets an `error` reply.

use crate::admission::AdmissionStore;
use crate::app_admission::{self, AppClients, AppRow, MAX_DAILY_CAP};
use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

const SOCKET: &str = "control.sock";
const REQUEST: &[u8] = b"provision\n";
/// Caps request reads at 128 bytes, enough for the longest `app-add` line of 80 bytes including its newline.
const REQUEST_LIMIT: usize = 128;
/// Caps reply reads at 65,536 bytes, enough for an `app-list` reply with all 256 rows.
const RESPONSE_LIMIT: u64 = 65_536;
const ERROR: &str = "error\n";
const TIMEOUT: Duration = Duration::from_secs(5);
pub const LIVE_ERROR: &str =
    "live provisioning failed; is the issuer running and are you its service user?";
pub const APP_ERROR: &str =
    "app admission command failed; check arguments and state, and whether the issuer is running";

pub struct ControlListener {
    listener: UnixListener,
    owner_uid: u32,
}

impl ControlListener {
    /// Hold the admission store's lock before binding so that the socket of a running issuer is not replaced.
    pub fn bind(dir: &Path) -> io::Result<Self> {
        let path = dir.join(SOCKET);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(&path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "control path is not a socket",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::other("control path is not a socket"));
        }
        // The state directory's `0700` permissions block other users from reaching the socket
        // between binding it and setting its mode to `0600`.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            owner_uid: metadata.uid(),
        })
    }

    /// Handles one connection at a time to limit the number of open connections and provisioning jobs.
    /// Accept errors stop the server. Errors in a request, store operation, or reply leave it running.
    /// Pass `None` for `apps` to disable application commands.
    pub async fn serve(
        self,
        store: Arc<AdmissionStore>,
        apps: Option<Arc<AppClients>>,
    ) -> io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            // Accept only a verified UID that matches the socket owner, even for root.
            if !matches!(stream.peer_cred(), Ok(cred) if cred.uid() == self.owner_uid) {
                continue;
            }
            handle(stream, store.clone(), apps.clone()).await;
        }
    }
}

fn valid_request(bytes: &[u8]) -> bool {
    bytes == REQUEST
}

/// Represents a management command whose name and cap, when present, are validated during parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppCommand {
    Add { name: String, cap: i64 },
    Revoke { name: String },
    Cap { name: String, cap: i64 },
    List,
}

/// Accepts decimal caps in `1..=MAX_DAILY_CAP` with no sign or leading zeros.
fn parse_cap(text: &str) -> Option<i64> {
    if text.is_empty()
        || text.len() > 6
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    let cap: i64 = text.parse().ok()?;
    (1..=MAX_DAILY_CAP).contains(&cap).then_some(cap)
}

/// Accepts one command line that separates fields with single spaces and ends in one `\n`.
pub fn parse_app(bytes: &[u8]) -> Option<AppCommand> {
    let line = std::str::from_utf8(bytes.strip_suffix(b"\n")?).ok()?;
    if line.contains('\n') {
        return None;
    }
    let name = |text: &str| app_admission::valid_name(text).then(|| text.to_owned());
    let fields: Vec<&str> = line.split(' ').collect();
    match fields.as_slice() {
        ["app-add", name_text, cap] => Some(AppCommand::Add {
            name: name(name_text)?,
            cap: parse_cap(cap)?,
        }),
        ["app-revoke", name_text] => Some(AppCommand::Revoke {
            name: name(name_text)?,
        }),
        ["app-cap", name_text, cap] => Some(AppCommand::Cap {
            name: name(name_text)?,
            cap: parse_cap(cap)?,
        }),
        ["app-list"] => Some(AppCommand::List),
        _ => None,
    }
}

/// Runs the command and formats its reply, or returns `None` to signal `error`.
/// Only a successful `app-add` includes a secret in its reply.
pub fn run_app(clients: &AppClients, command: AppCommand, now: i64) -> Option<String> {
    match command {
        AppCommand::Add { name, cap } => clients
            .add(&name, cap)
            .ok()
            .flatten()
            .map(|key| format!("ok {key}\n")),
        AppCommand::Revoke { name } => clients
            .revoke(&name)
            .ok()
            .filter(|changed| *changed)
            .map(|_| "ok\n".to_owned()),
        AppCommand::Cap { name, cap } => clients
            .set_cap(&name, cap)
            .ok()
            .filter(|changed| *changed)
            .map(|_| "ok\n".to_owned()),
        AppCommand::List => clients.list(now).ok().map(|rows| {
            let mut reply = String::new();
            for AppRow {
                name,
                daily_cap,
                issued,
                revoked,
            } in rows
            {
                let state = if revoked { "revoked" } else { "active" };
                reply.push_str(&format!("app {name} {daily_cap} {issued} {state}\n"));
            }
            reply.push_str("end\n");
            reply
        }),
    }
}

/// Stops reading after a chunk contains a newline or after `REQUEST_LIMIT` bytes.
async fn read_request(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut buffer = [0; REQUEST_LIMIT];
    let mut length = 0;
    while length < buffer.len() {
        let read = stream.read(&mut buffer[length..]).await?;
        if read == 0 {
            break;
        }
        length += read;
        if buffer[..length].contains(&b'\n') {
            break;
        }
    }
    Ok(buffer[..length].to_vec())
}

async fn respond(
    request: Vec<u8>,
    store: Arc<AdmissionStore>,
    apps: Option<Arc<AppClients>>,
) -> String {
    if valid_request(&request) {
        let invitation = tokio::task::spawn_blocking(move || {
            let seconds = app_admission::now_seconds().ok_or(())?;
            store.provision(seconds).map_err(|_| ())
        })
        .await
        .ok()
        .and_then(Result::ok);
        // Provisioning commits before the reply is written, so a failed or timed-out write
        // leaves the invitation valid until it expires after 24 hours. Let it expire.
        return invitation.map_or_else(|| ERROR.to_owned(), |code| format!("ok {code}\n"));
    }
    let (Some(apps), Some(command)) = (apps, parse_app(&request)) else {
        return ERROR.to_owned();
    };
    tokio::task::spawn_blocking(move || {
        let now = app_admission::now_seconds()?;
        run_app(&apps, command, now)
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| ERROR.to_owned())
}

async fn handle(mut stream: UnixStream, store: Arc<AdmissionStore>, apps: Option<Arc<AppClients>>) {
    let response = match timeout(TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(request)) => respond(request, store, apps).await,
        _ => ERROR.to_owned(),
    };
    let _ = timeout(TIMEOUT, stream.write_all(response.as_bytes())).await;
}

fn validate_response(bytes: &[u8]) -> Option<&str> {
    if bytes.len() != 47 || !bytes.starts_with(b"ok ") || !bytes.ends_with(b"\n") {
        return None;
    }
    let code = &bytes[3..46];
    if !code
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    std::str::from_utf8(code).ok()
}

/// Checks the reply format for the command so that unexpected responses are not displayed.
fn valid_app_response(command: &AppCommand, bytes: &[u8]) -> bool {
    match command {
        AppCommand::Add { .. } => {
            bytes.len() == 51
                && bytes.starts_with(b"ok fba_")
                && bytes.ends_with(b"\n")
                && bytes[7..50]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        }
        AppCommand::Revoke { .. } | AppCommand::Cap { .. } => bytes == b"ok\n",
        AppCommand::List => {
            let Ok(text) = std::str::from_utf8(bytes) else {
                return false;
            };
            let Some(rows) = text.strip_suffix("end\n") else {
                return false;
            };
            rows.split_inclusive('\n').all(|line| {
                let Some(fields) = line
                    .strip_suffix('\n')
                    .and_then(|line| line.strip_prefix("app "))
                else {
                    return false;
                };
                let fields: Vec<&str> = fields.split(' ').collect();
                fields.len() == 4
                    && app_admission::valid_name(fields[0])
                    && fields[1].parse::<i64>().is_ok()
                    && fields[2].parse::<i64>().is_ok()
                    && matches!(fields[3], "active" | "revoked")
            })
        }
    }
}

async fn live_app(
    mut stream: UnixStream,
    command: &AppCommand,
    line: &str,
) -> Result<String, &'static str> {
    timeout(TIMEOUT, stream.write_all(line.as_bytes()))
        .await
        .map_err(|_| APP_ERROR)?
        .map_err(|_| APP_ERROR)?;
    let mut response = Vec::new();
    timeout(
        TIMEOUT,
        stream.take(RESPONSE_LIMIT).read_to_end(&mut response),
    )
    .await
    .map_err(|_| APP_ERROR)?
    .map_err(|_| APP_ERROR)?;
    if !valid_app_response(command, &response) {
        return Err(APP_ERROR);
    }
    String::from_utf8(response).map_err(|_| APP_ERROR)
}

/// Takes the store's lock for offline maintenance so that it cannot run while an issuer holds the store open.
fn offline_app(dir: &Path, command: AppCommand) -> Result<String, &'static str> {
    if !app_admission::enabled(dir).map_err(|_| APP_ERROR)? {
        return Err(APP_ERROR);
    }
    let clients = AppClients::open(dir).map_err(|_| APP_ERROR)?;
    let now = app_admission::now_seconds().ok_or(APP_ERROR)?;
    run_app(&clients, command, now).ok_or(APP_ERROR)
}

/// Sends the command to the live socket and only runs it offline if the socket is missing
/// or refuses the connection. Once connected, return the live result, including any error.
pub async fn app_command(dir: &Path, line: &str) -> Result<String, &'static str> {
    let command = parse_app(line.as_bytes()).ok_or(APP_ERROR)?;
    match timeout(TIMEOUT, UnixStream::connect(dir.join(SOCKET))).await {
        Ok(Ok(stream)) => live_app(stream, &command, line).await,
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            offline_app(dir, command)
        }
        _ => Err(APP_ERROR),
    }
}

/// Requests one invitation from the live issuer and returns only the validated code.
pub async fn provision_live(dir: &Path) -> Result<String, &'static str> {
    let mut stream = timeout(TIMEOUT, UnixStream::connect(dir.join(SOCKET)))
        .await
        .map_err(|_| LIVE_ERROR)?
        .map_err(|_| LIVE_ERROR)?;
    timeout(TIMEOUT, stream.write_all(REQUEST))
        .await
        .map_err(|_| LIVE_ERROR)?
        .map_err(|_| LIVE_ERROR)?;
    let mut response = Vec::with_capacity(128);
    // Read until the server closes the connection after its reply, up to 128 bytes.
    timeout(TIMEOUT, stream.take(128).read_to_end(&mut response))
        .await
        .map_err(|_| LIVE_ERROR)?
        .map_err(|_| LIVE_ERROR)?;
    validate_response(&response)
        .map(str::to_owned)
        .ok_or(LIVE_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{fs::symlink, net::UnixListener as StdUnixListener},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn setup() -> (tempfile::TempDir, Arc<AdmissionStore>) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let db = dir.path().join("admission.sqlite");
        let generation = dir.path().join("generation");
        AdmissionStore::initialize(&db, &generation).unwrap();
        let store = Arc::new(AdmissionStore::open(db, generation).unwrap());
        (dir, store)
    }

    #[test]
    fn request_must_be_exact() {
        assert!(valid_request(b"provision\n"));
        for request in [
            b"".as_slice(),
            b"provision",
            b"PROVISION\n",
            b"provision\r\n",
            b" provision\n",
            b"provision\n\n",
            b"provision\nextra",
            b"provision\0\n",
            b"provisionprovision\n",
        ] {
            assert!(!valid_request(request));
        }
    }

    #[test]
    fn response_requires_exact_framing_and_base64url_characters() {
        let code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
        let response = format!("ok {code}\n");
        assert_eq!(validate_response(response.as_bytes()), Some(code));
        for character in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" {
            let code = (*character as char).to_string().repeat(43);
            let response = format!("ok {code}\n");
            assert_eq!(validate_response(response.as_bytes()), Some(code.as_str()));
        }
        for response in [
            String::new(),
            "error\n".to_owned(),
            format!("OK {code}\n"),
            format!("ok {code}"),
            format!("ok {code}\r\n"),
            format!("ok {code}\nextra"),
            format!("ok {}\n", "A".repeat(42)),
            format!("ok {}\n", "A".repeat(44)),
            format!("ok {}=\n", "A".repeat(42)),
            format!("ok {}+\n", "A".repeat(42)),
            format!("ok {}/\n", "A".repeat(42)),
            format!("ok {} \n", "A".repeat(42)),
            format!("ok {}\0\n", "A".repeat(42)),
            format!("ok {}é\n", "A".repeat(41)),
        ] {
            assert!(validate_response(response.as_bytes()).is_none());
        }
    }

    #[tokio::test]
    async fn live_provisioning_consumes_exactly_once() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, store) = setup();
        let listener = ControlListener::bind(dir.path()).unwrap();
        let metadata = fs::symlink_metadata(dir.path().join(SOCKET)).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let server = tokio::spawn(listener.serve(store.clone(), None));

        // An unknown request returns an error and leaves the listener open for the next request.
        let mut stream = UnixStream::connect(dir.path().join(SOCKET)).await.unwrap();
        stream.write_all(b"unknown\n").await.unwrap();
        let mut response = Vec::new();
        timeout(TIMEOUT, stream.take(128).read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"error\n");

        let first = provision_live(dir.path()).await.unwrap();
        let second = provision_live(dir.path()).await.unwrap();
        assert!(first != second, "invitations must differ");
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        for code in [first, second] {
            assert!(store.consume(&code, now).unwrap());
            assert!(!store.consume(&code, now).unwrap());
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn app_requests_parse_exactly() {
        let name = "a".repeat(64);
        assert_eq!(parse_app(b"app-list\n"), Some(AppCommand::List));
        assert_eq!(
            parse_app(b"app-add alpha 2\n"),
            Some(AppCommand::Add {
                name: "alpha".to_owned(),
                cap: 2
            })
        );
        assert_eq!(
            parse_app(b"app-add a-1 100000\n"),
            Some(AppCommand::Add {
                name: "a-1".to_owned(),
                cap: 100_000
            })
        );
        assert_eq!(
            parse_app(format!("app-add {name} 1\n").as_bytes()),
            Some(AppCommand::Add {
                name: name.clone(),
                cap: 1
            })
        );
        assert_eq!(
            parse_app(b"app-revoke alpha\n"),
            Some(AppCommand::Revoke {
                name: "alpha".to_owned()
            })
        );
        assert_eq!(
            parse_app(b"app-cap alpha 7\n"),
            Some(AppCommand::Cap {
                name: "alpha".to_owned(),
                cap: 7
            })
        );
        for line in [
            "".to_owned(),
            "app-list".to_owned(),
            "app-list\n\n".to_owned(),
            "app-list x\n".to_owned(),
            " app-list\n".to_owned(),
            "app-list \n".to_owned(),
            "APP-LIST\n".to_owned(),
            "app-list\r\n".to_owned(),
            "app-add alpha 2".to_owned(),
            "app-add alpha 2\r\n".to_owned(),
            "app-add  alpha 2\n".to_owned(),
            "app-add alpha  2\n".to_owned(),
            "app-add alpha 2 \n".to_owned(),
            "app-add Alpha 2\n".to_owned(),
            "app-add -alpha 2\n".to_owned(),
            "app-add alpha_b 2\n".to_owned(),
            "app-add a.b 2\n".to_owned(),
            "app-add alpha 0\n".to_owned(),
            "app-add alpha 100001\n".to_owned(),
            "app-add alpha 1000000\n".to_owned(),
            "app-add alpha 01\n".to_owned(),
            "app-add alpha +1\n".to_owned(),
            "app-add alpha -1\n".to_owned(),
            "app-add alpha 1e3\n".to_owned(),
            "app-add alpha 1\nextra\n".to_owned(),
            "app-add alpha 1\0\n".to_owned(),
            "app-add alpha 1 extra\n".to_owned(),
            "app-add alpha\n".to_owned(),
            "app-add\n".to_owned(),
            format!("app-add {}b 1\n", name),
            "app-revoke\n".to_owned(),
            "app-revoke alpha extra\n".to_owned(),
            "app-cap alpha\n".to_owned(),
            "provision\n\n".to_owned(),
        ] {
            assert_eq!(parse_app(line.as_bytes()), None, "{line:?}");
        }
    }

    #[test]
    fn app_responses_have_exact_shapes_and_store_effects() {
        let _spawn_guard = crate::SPAWN_LOCK.blocking_read();
        let (dir, _store) = setup();
        app_admission::initialize(dir.path()).unwrap();
        let clients = AppClients::open(dir.path()).unwrap();
        let now = 20_000 * 86_400;
        let add = AppCommand::Add {
            name: "alpha".to_owned(),
            cap: 2,
        };
        let reply = run_app(&clients, add.clone(), now).unwrap();
        assert!(
            valid_app_response(&add, reply.as_bytes()),
            "add reply shape"
        );
        assert_eq!(reply.len(), 51);
        assert!(run_app(&clients, add, now).is_none(), "active name refused");
        let revoke_missing = AppCommand::Revoke {
            name: "missing".to_owned(),
        };
        assert_eq!(run_app(&clients, revoke_missing, now), None);
        let cap = AppCommand::Cap {
            name: "alpha".to_owned(),
            cap: 3,
        };
        assert_eq!(run_app(&clients, cap.clone(), now).as_deref(), Some("ok\n"));
        assert!(valid_app_response(&cap, b"ok\n"));
        let revoke = AppCommand::Revoke {
            name: "alpha".to_owned(),
        };
        assert_eq!(
            run_app(&clients, revoke.clone(), now).as_deref(),
            Some("ok\n")
        );
        assert_eq!(run_app(&clients, cap, now), Some("ok\n".to_owned()));
        assert!(run_app(
            &clients,
            AppCommand::Cap {
                name: "alpha".to_owned(),
                cap: 0
            },
            now
        )
        .is_none());
        let add_beta = AppCommand::Add {
            name: "beta".to_owned(),
            cap: 1,
        };
        run_app(&clients, add_beta, now).unwrap();
        let list = run_app(&clients, AppCommand::List, now).unwrap();
        assert_eq!(list, "app alpha 3 0 revoked\napp beta 1 0 active\nend\n");
        assert!(valid_app_response(&AppCommand::List, list.as_bytes()));
        for invalid in [
            "app alpha 3 0 revoked\n",
            "app alpha 3 0 revoked\nend",
            "app alpha 3 0 gone\nend\n",
            "app Alpha 3 0 active\nend\n",
            "app alpha x 0 active\nend\n",
            "app alpha 3 0 active extra\nend\n",
            "ok\n",
        ] {
            assert!(
                !valid_app_response(&AppCommand::List, invalid.as_bytes()),
                "{invalid:?}"
            );
        }
        assert!(valid_app_response(&AppCommand::List, b"end\n"));
        assert!(valid_app_response(
            &AppCommand::Add {
                name: "x".to_owned(),
                cap: 1
            },
            format!("ok fba_{}\n", "A".repeat(43)).as_bytes()
        ));
        assert!(!valid_app_response(
            &AppCommand::Add {
                name: "x".to_owned(),
                cap: 1
            },
            format!("ok fba_{}\n", "A".repeat(42)).as_bytes()
        ));
    }

    #[tokio::test]
    async fn app_commands_are_error_when_disabled_and_never_fall_back_after_a_reply() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, store) = setup();
        app_admission::initialize(dir.path()).unwrap();
        let listener = ControlListener::bind(dir.path()).unwrap();
        let server = tokio::spawn(listener.serve(store, None));
        // The server returns `error` because application admission is disabled. An offline retry
        // could run against the store on disk, so the client must return the live error.
        let mut stream = UnixStream::connect(dir.path().join(SOCKET)).await.unwrap();
        stream.write_all(b"app-list\n").await.unwrap();
        let mut response = Vec::new();
        timeout(TIMEOUT, stream.take(128).read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"error\n");
        assert_eq!(app_command(dir.path(), "app-list\n").await, Err(APP_ERROR));
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        // Removing the socket allows the same command to run offline under the store's lock.
        assert_eq!(
            app_command(dir.path(), "app-list\n").await.unwrap(),
            "end\n"
        );
    }

    #[tokio::test]
    async fn live_app_commands_are_exact_over_the_socket() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, store) = setup();
        app_admission::initialize(dir.path()).unwrap();
        let clients = Arc::new(AppClients::open(dir.path()).unwrap());
        let listener = ControlListener::bind(dir.path()).unwrap();
        let server = tokio::spawn(listener.serve(store, Some(clients.clone())));
        let key = app_command(dir.path(), "app-add alpha 2\n").await.unwrap();
        assert!(key.starts_with("ok fba_") && key.ends_with('\n') && key.len() == 51);
        assert_eq!(
            app_command(dir.path(), "app-add alpha 2\n").await,
            Err(APP_ERROR),
            "active name"
        );
        assert_eq!(
            app_command(dir.path(), "app-cap alpha 5\n").await.unwrap(),
            "ok\n"
        );
        assert_eq!(
            app_command(dir.path(), "app-revoke alpha\n").await.unwrap(),
            "ok\n"
        );
        assert_eq!(
            app_command(dir.path(), "app-list\n").await.unwrap(),
            "app alpha 5 0 revoked\nend\n"
        );
        assert_eq!(
            app_command(dir.path(), "app-list x\n").await,
            Err(APP_ERROR)
        );
        // Sending a malformed line over the socket returns exactly `error\n`.
        let mut stream = UnixStream::connect(dir.path().join(SOCKET)).await.unwrap();
        stream.write_all(b"app-add Bad 1\n").await.unwrap();
        let mut response = Vec::new();
        timeout(TIMEOUT, stream.take(128).read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"error\n");
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        drop(clients);
        // Shutdown releases the lock, so offline commands can read the same stored state.
        assert_eq!(
            app_command(dir.path(), "app-list\n").await.unwrap(),
            "app alpha 5 0 revoked\nend\n"
        );
    }

    #[tokio::test]
    async fn stale_socket_is_replaced() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, store) = setup();
        let path = dir.path().join(SOCKET);
        let stale = StdUnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let listener = ControlListener::bind(dir.path()).unwrap();
        let server = tokio::spawn(listener.serve(store, None));
        assert!(provision_live(dir.path()).await.is_ok());
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn regular_file_and_symlinks_are_refused_without_changes() {
        let _spawn_guard = crate::SPAWN_LOCK.read().await;
        let (dir, _store) = setup();
        let path = dir.path().join(SOCKET);
        fs::write(&path, b"do not remove").unwrap();
        assert!(ControlListener::bind(dir.path()).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"do not remove");
        fs::remove_file(&path).unwrap();

        let target = dir.path().join("target");
        fs::write(&target, b"do not follow").unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode();
        symlink(&target, &path).unwrap();
        assert!(ControlListener::bind(dir.path()).is_err());
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"do not follow");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode(), mode);
        fs::remove_file(&path).unwrap();

        let socket_target = dir.path().join("target.sock");
        let _socket = StdUnixListener::bind(&socket_target).unwrap();
        symlink(&socket_target, &path).unwrap();
        assert!(ControlListener::bind(dir.path()).is_err());
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(fs::symlink_metadata(&socket_target)
            .unwrap()
            .file_type()
            .is_socket());
        fs::remove_file(&path).unwrap();

        symlink(dir.path().join("missing"), &path).unwrap();
        assert!(ControlListener::bind(dir.path()).is_err());
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
