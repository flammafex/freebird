//! CLI regressions for offline staging only; activation/rotation remains unsupported.
use freebird_crypto::privacy_pass::PublicKey;
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_freebird-privacy-pass-service");
const TIMEOUT: Duration = Duration::from_secs(60);

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(command: &str, state: &Path, extra: &[&Path]) -> Output {
    let mut child = Process(
        Command::new(BIN)
            .arg(command)
            .arg(state)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn CLI"),
    );
    let deadline = Instant::now() + TIMEOUT;
    while child.0.try_wait().expect("poll CLI").is_none() {
        assert!(Instant::now() < deadline, "{command} timed out");
        thread::sleep(Duration::from_millis(25));
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    Output {
        status: child.0.wait().unwrap(),
        stdout,
        stderr,
    }
}

fn success(command: &str, state: &Path, extra: &[&Path]) -> Output {
    let output = cli(command, state, extra);
    assert!(output.status.success(), "{command} failed: {:?}", output);
    output
}

fn status(state: &Path) -> Vec<(String, String)> {
    let output = success("issuer-key-status", state, &[]);
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 2, "status must contain only public IDs");
            assert!(matches!(fields[0], "active" | "staged"));
            assert_eq!(fields[1].len(), 64);
            assert!(fields[1]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
            (fields[0].to_owned(), fields[1].to_owned())
        })
        .collect()
}

#[test]
fn offline_staging_exports_public_key_without_activation() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("issuer");
    let export = temp.path().join("candidate.der");
    success("init-issuer", &state, &[]);
    let initial = status(&state);
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].0, "active");

    assert!(!cli("export-staged-spki", &state, &[&export])
        .status
        .success());
    assert!(!export.exists());
    success("stage-issuer-key", &state, &[]);
    let staged = status(&state);
    assert_eq!(staged.len(), 2);
    assert_eq!(staged[0], initial[0]);
    assert_eq!(staged[1].0, "staged");
    assert_ne!(staged[1].1, initial[0].1);

    success("export-staged-spki", &state, &[&export]);
    assert_eq!(
        fs::metadata(&export).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = fs::read(&export).unwrap();
    let public = PublicKey::from_spki(&bytes).expect("canonical public SPKI");
    assert_eq!(public.to_spki(), bytes);
    let id: String = public.key_id().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(id, staged[1].1);
    assert!(!cli("export-staged-spki", &state, &[&export])
        .status
        .success());
    assert_eq!(fs::read(&export).unwrap(), bytes);
    assert!(!cli("stage-issuer-key", &state, &[]).status.success());
    // Each invocation reopens durable state in a new process.
    assert_eq!(status(&state), staged);
}

#[test]
fn legacy_signing_pk8_is_rejected_without_reset() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("legacy");
    fs::create_dir(&state).unwrap();
    let fixture = b"explicit legacy signing.pk8 fixture";
    fs::write(state.join("signing.pk8"), fixture).unwrap();
    let export = temp.path().join("candidate.der");
    for command in [
        "init-issuer",
        "issuer-key-status",
        "stage-issuer-key",
        "export-staged-spki",
    ] {
        let extra = if command == "export-staged-spki" {
            vec![export.as_path()]
        } else {
            vec![]
        };
        let output = cli(command, &state, &extra);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("signing.pk8 exists"));
        assert_eq!(fs::read(state.join("signing.pk8")).unwrap(), fixture);
        assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
    }
    assert!(!export.exists());
}

fn directory_ready(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(200)) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    if stream.write_all(b"GET /.well-known/private-token-issuer-directory HTTP/1.1\r\nHost: issuer.test\r\nConnection: close\r\n\r\n").is_err() {
        return false;
    }
    let mut response = String::new();
    if stream.take(65536).read_to_string(&mut response).is_err() {
        return false;
    }
    response.starts_with("HTTP/1.1 200 ")
        && response.contains("application/private-token-issuer-directory")
        && response.contains("token-keys")
}

#[test]
fn serving_holds_key_store_lock_until_process_stops() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("issuer");
    success("init-issuer", &state, &[]);
    let initial = status(&state);
    let reservation = TcpListener::bind("127.0.0.1:0").expect("loopback test environment");
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut server = Process(
        Command::new(BIN)
            .arg("serve-issuer")
            .arg(&state)
            .args([
                "issuer.test",
                "https://issuer.test/private-token/issue",
                &address.to_string(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + TIMEOUT;
    loop {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "issuer exited before readiness (possible port race)"
        );
        if directory_ready(address) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "directory readiness timed out; loopback environment or port race"
        );
        thread::sleep(Duration::from_millis(25));
    }
    let output = cli("stage-issuer-key", &state, &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already owned"));
    drop(server);
    assert_eq!(status(&state), initial);
    success("stage-issuer-key", &state, &[]);
    let staged = status(&state);
    assert_eq!(staged.len(), 2);
    assert_eq!(staged[0], initial[0]);
    assert_eq!(staged[1].0, "staged");
}
