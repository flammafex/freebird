//! CLI regressions for offline staging, export, and status formatting.
//! Activation and retirement are covered in key_rotation.rs.
use freebird_crypto::privacy_pass::PublicKey;
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BIN: &str = env!("CARGO_BIN_EXE_freebird-privacy-pass-service");
const TIMEOUT: Duration = Duration::from_secs(60);
const ZERO_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(args: &[&str]) -> Output {
    let mut child = Process(
        Command::new(BIN)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn CLI"),
    );
    let deadline = Instant::now() + TIMEOUT;
    while child.0.try_wait().expect("poll CLI").is_none() {
        assert!(Instant::now() < deadline, "{args:?} timed out");
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

fn success(args: &[&str]) -> Output {
    let output = cli(args);
    assert!(output.status.success(), "{args:?} failed: {output:?}");
    output
}

fn refused(args: &[&str]) -> Output {
    let output = cli(args);
    assert!(!output.status.success(), "{args:?} unexpectedly succeeded");
    output
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Hour-aligned instant ten years out, unreachable by any real-clock server here.
fn far_future() -> u64 {
    (unix_now() / 3600 + 24 * 365 * 10) * 3600
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    state: String,
    id: String,
    activation: String,
    issuance_end: String,
    acceptance_deadline: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Status {
    high_water: u64,
    rows: Vec<Row>,
}

fn seconds_or_dash(field: &str) -> String {
    if field == "-" {
        return field.to_owned();
    }
    assert!(
        !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit()),
        "time field must be decimal seconds or '-': {field}"
    );
    field.to_owned()
}

/// Parses the frozen format: `now`, `high-water`, then one row per key.
fn parse_status(output: &Output) -> Status {
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    let mut lines = text.lines();
    let now = lines.next().unwrap().strip_prefix("now ").unwrap();
    now.parse::<u64>().expect("now is decimal seconds");
    let high = lines.next().unwrap().strip_prefix("high-water ").unwrap();
    let high_water = high.parse::<u64>().expect("high-water is decimal seconds");
    let rows = lines
        .map(|line| {
            let fields: Vec<_> = line.split(' ').collect();
            assert_eq!(fields.len(), 5, "row: {line}");
            assert!(matches!(
                fields[0],
                "staged" | "scheduled" | "active" | "retired-for-issuance" | "retired"
            ));
            assert_eq!(fields[1].len(), 64);
            assert!(fields[1]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            Row {
                state: fields[0].to_owned(),
                id: fields[1].to_owned(),
                activation: seconds_or_dash(fields[2]),
                issuance_end: seconds_or_dash(fields[3]),
                acceptance_deadline: seconds_or_dash(fields[4]),
            }
        })
        .collect();
    Status { high_water, rows }
}

fn status(state: &Path) -> Status {
    parse_status(&success(&["issuer-key-status", state.to_str().unwrap()]))
}

#[test]
fn offline_staging_exports_public_key_without_activation() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("issuer");
    let export = temp.path().join("candidate.der");
    let state_arg = state.to_str().unwrap();
    let export_arg = export.to_str().unwrap();
    success(&["init-issuer", state_arg]);
    let initial = status(&state);
    assert_eq!(initial.rows.len(), 1);
    assert_eq!(initial.rows[0].state, "active");
    assert_eq!(initial.rows[0].activation, "0");
    assert_eq!(initial.rows[0].issuance_end, "-");
    assert_eq!(initial.rows[0].acceptance_deadline, "-");

    refused(&["export-issuer-spki", state_arg, ZERO_ID, export_arg]);
    assert!(!export.exists());
    success(&["stage-issuer-key", state_arg]);
    let staged = status(&state);
    assert_eq!(staged.rows.len(), 2);
    assert_eq!(staged.rows[0], initial.rows[0]);
    assert_eq!(staged.rows[1].state, "staged");
    assert_eq!(staged.rows[1].activation, "-");
    assert_ne!(staged.rows[1].id, initial.rows[0].id);
    assert!(staged.high_water >= initial.high_water);
    let staged_id = staged.rows[1].id.clone();

    refused(&["stage-issuer-key", state_arg]);
    success(&["export-issuer-spki", state_arg, &staged_id, export_arg]);
    assert_eq!(
        fs::metadata(&export).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = fs::read(&export).unwrap();
    let public = PublicKey::from_spki(&bytes).expect("canonical public SPKI");
    assert_eq!(public.to_spki(), bytes);
    let id: String = public.key_id().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(id, staged_id);
    // Never overwrite an existing export.
    refused(&["export-issuer-spki", state_arg, &staged_id, export_arg]);
    assert_eq!(fs::read(&export).unwrap(), bytes);
    // The genesis key is also exportable by its public ID.
    let genesis_id = &initial.rows[0].id;
    let genesis_export = temp.path().join("genesis.der");
    success(&[
        "export-issuer-spki",
        state_arg,
        genesis_id,
        genesis_export.to_str().unwrap(),
    ]);
    assert_eq!(
        PublicKey::from_spki(&fs::read(&genesis_export).unwrap())
            .unwrap()
            .key_id()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        *genesis_id
    );
    // Each invocation reopens durable state in a new process.
    assert_eq!(status(&state).rows, staged.rows);
}

#[test]
fn malformed_key_ids_and_times_are_refused_without_state_change() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("issuer");
    let export = temp.path().join("candidate.der");
    let state_arg = state.to_str().unwrap();
    success(&["init-issuer", state_arg]);
    let before = status(&state);
    let short = "ab".repeat(31);
    let upper_out_of_set = "G".repeat(64);
    refused(&[
        "export-issuer-spki",
        state_arg,
        &short,
        export.to_str().unwrap(),
    ]);
    refused(&[
        "export-issuer-spki",
        state_arg,
        &upper_out_of_set,
        export.to_str().unwrap(),
    ]);
    refused(&["activate-issuer-key", state_arg, ZERO_ID, "7200x"]);
    refused(&["activate-issuer-key", state_arg, ZERO_ID, "-7200"]);
    refused(&["activate-issuer-key", state_arg, &short, "7200"]);
    refused(&["activate-issuer-key", state_arg, &upper_out_of_set, "7200"]);
    assert!(!export.exists());
    assert_eq!(status(&state), before);
}

#[test]
fn legacy_signing_pk8_is_rejected_without_reset() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("legacy");
    fs::create_dir(&state).unwrap();
    let fixture = b"explicit legacy signing.pk8 fixture";
    fs::write(state.join("signing.pk8"), fixture).unwrap();
    let export = temp.path().join("candidate.der");
    let state_arg = state.to_str().unwrap();
    let export_arg = export.to_str().unwrap();
    let far = far_future().to_string();
    let commands: [Vec<&str>; 7] = [
        vec!["init-issuer", state_arg],
        vec!["issuer-key-status", state_arg],
        vec!["stage-issuer-key", state_arg],
        vec!["export-issuer-spki", state_arg, ZERO_ID, export_arg],
        vec!["activate-issuer-key", state_arg, ZERO_ID, &far],
        vec!["retire-issuer-key", state_arg, ZERO_ID],
        vec![
            "serve-issuer",
            state_arg,
            "issuer.test",
            "https://issuer.test/private-token/issue",
            "127.0.0.1:0",
        ],
    ];
    for args in commands {
        let output = refused(&args);
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
    let state_arg = state.to_str().unwrap();
    success(&["init-issuer", state_arg]);
    let initial = status(&state);
    let reservation = TcpListener::bind("127.0.0.1:0").expect("loopback test environment");
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut server = Process(
        Command::new(BIN)
            .args([
                "serve-issuer",
                state_arg,
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
    let far = far_future().to_string();
    for args in [
        vec!["stage-issuer-key", state_arg],
        vec!["issuer-key-status", state_arg],
        vec!["activate-issuer-key", state_arg, ZERO_ID, &far],
    ] {
        let output = refused(&args);
        assert!(String::from_utf8_lossy(&output.stderr).contains("already owned"));
    }
    drop(server);
    assert_eq!(status(&state).rows, initial.rows);
    success(&["stage-issuer-key", state_arg]);
    let staged = status(&state);
    assert_eq!(staged.rows.len(), 2);
    assert_eq!(staged.rows[0], initial.rows[0]);
    assert_eq!(staged.rows[1].state, "staged");
}
