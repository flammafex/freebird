//! Operator-only live invitation provisioning over the Issuer's local socket.

use crate::admission::AdmissionStore;
use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

const SOCKET: &str = "control.sock";
const REQUEST: &[u8] = b"provision\n";
const TIMEOUT: Duration = Duration::from_secs(5);
pub const LIVE_ERROR: &str =
    "live provisioning failed; is the issuer running and are you its service user?";

pub struct ControlListener {
    listener: UnixListener,
    owner_uid: u32,
}

impl ControlListener {
    /// The caller must already hold the admission store's lifetime lock, so
    /// another Issuer cannot own the socket being replaced.
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
        // State directories are private (0700), so setting 0600 after bind
        // cannot expose the socket to other users in the intervening window.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            owner_uid: metadata.uid(),
        })
    }

    /// Sequential handling bounds provisioning work and connection resources.
    /// Listener errors are fatal; individual protocol/store/write errors are not.
    pub async fn serve(self, store: Arc<AdmissionStore>) -> io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            // No root bypass. Failure to obtain credentials also fails closed.
            if !matches!(stream.peer_cred(), Ok(cred) if cred.uid() == self.owner_uid) {
                continue;
            }
            handle(stream, store.clone()).await;
        }
    }
}

fn valid_request(bytes: &[u8]) -> bool {
    bytes == REQUEST
}

async fn read_request(stream: &mut UnixStream) -> io::Result<bool> {
    let mut buffer = [0; 16];
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
    Ok(valid_request(&buffer[..length]))
}

async fn handle(mut stream: UnixStream, store: Arc<AdmissionStore>) {
    let invitation = if matches!(
        timeout(TIMEOUT, read_request(&mut stream)).await,
        Ok(Ok(true))
    ) {
        tokio::task::spawn_blocking(move || {
            let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            store.provision(i64::try_from(seconds)?)
        })
        .await
        .ok()
        .and_then(Result::ok)
    } else {
        None
    };
    let response = invitation.map_or_else(|| "error\n".to_owned(), |code| format!("ok {code}\n"));
    // Provisioning is already durable. A failed/timed-out write orphans the
    // invitation until its 24h expiry: never retry, undo, or refund it.
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

/// Returns the sole invitation, never including protocol text or diagnostics.
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
    // Read to EOF (the server closes after its one reply), capped at 128 bytes.
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
    use std::os::unix::{fs::symlink, net::UnixListener as StdUnixListener};

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
        let (dir, store) = setup();
        let listener = ControlListener::bind(dir.path()).unwrap();
        let metadata = fs::symlink_metadata(dir.path().join(SOCKET)).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let server = tokio::spawn(listener.serve(store.clone()));

        // An unknown request must fail without taking down the listener.
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

    #[tokio::test]
    async fn stale_socket_is_replaced() {
        let (dir, store) = setup();
        let path = dir.path().join(SOCKET);
        let stale = StdUnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let listener = ControlListener::bind(dir.path()).unwrap();
        let server = tokio::spawn(listener.serve(store));
        assert!(provision_live(dir.path()).await.is_ok());
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn regular_file_and_symlinks_are_refused_without_changes() {
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
