use super::*;
use crate::sybil_resistance::admission::AdmissionExecutor;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
#[ignore = "requires FREEBIRD_REDIS_LIVE_URL pointing to a numeric IP or Unix Redis endpoint"]
async fn live_redis_health_and_confirmed_duplicate() {
    let url = std::env::var("FREEBIRD_REDIS_LIVE_URL")
        .expect("set FREEBIRD_REDIS_LIVE_URL to a numeric IP or Unix Redis endpoint");
    // The production constructor enforces the approved no-DNS endpoint policy.
    let store = RedisReplayStore::new(&url, "freebird:test:replay:live")
        .expect("invalid live Redis replay configuration");
    let key = uuid::Uuid::new_v4().to_string();
    AdmissionExecutor::new(1)
        .run(move || {
            store.health_check()?;
            let ttl = Duration::from_secs(60);
            store.mark_once("opt-in", &key, ttl)?;
            let duplicate = store
                .mark_once("opt-in", &key, ttl)
                .expect_err("second insertion must be a confirmed duplicate");
            assert!(
                !duplicate.is::<AdmissionUnavailable>(),
                "duplicate must not be an availability failure"
            );
            assert_eq!(duplicate.to_string(), "Sybil proof already used");
            // The unique test key expires naturally; no cleanup command is needed.
            Ok(())
        })
        .await
        .expect("live Redis health and replay checks must succeed");
}

// Minimal RESP peer: acknowledge initialization, then stall or reply to one command.
async fn command(reader: &mut BufReader<tokio::net::TcpStream>) -> Vec<String> {
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
    let mut args = Vec::new();
    for _ in 0..count {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let len: usize = line.trim().strip_prefix('$').unwrap().parse().unwrap();
        let mut bytes = vec![0; len + 2];
        reader.read_exact(&mut bytes).await.unwrap();
        args.push(String::from_utf8(bytes[..len].to_vec()).unwrap());
    }
    args
}

async fn run_peer(
    stall_init: bool,
    health: bool,
    reply: Option<&'static [u8]>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("redis://{}/", listener.local_addr().unwrap());
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        loop {
            let args = command(&mut reader).await;
            let initialization = args[0] == "CLIENT";
            if initialization && !stall_init {
                reader.get_mut().write_all(b"+OK\r\n").await.unwrap();
                continue;
            }
            if !stall_init {
                assert_eq!(args[0], if health { "PING" } else { "SET" });
                if !health {
                    assert_eq!(args, ["SET", "test:pow:proof", "1", "NX", "EX", "601"]);
                }
            }
            if let Some(reply) = reply {
                reader.get_mut().write_all(reply).await.unwrap();
            }
            // The one-shot connection must close after reply or timeout. During
            // initialization redis can already have pipelined another CLIENT.
            let mut remaining = Vec::new();
            reader.read_to_end(&mut remaining).await.unwrap();
            break;
        }
    });
    let mut store = RedisReplayStore::new(&url, "test").unwrap();
    store.operation_timeout = Duration::from_millis(150);
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        AdmissionExecutor::new(1).run(move || {
            if health {
                store.health_check()
            } else {
                store.mark_once("pow", "proof", Duration::from_secs(601))
            }
        }),
    )
    .await
    .expect("operation must be bounded");
    tokio::time::timeout(Duration::from_secs(3), peer)
        .await
        .expect("connection must close")
        .unwrap();
    result
}

#[tokio::test]
async fn refused_connection_is_typed_unavailability() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let store = RedisReplayStore::new(&format!("redis://{address}/"), "test").unwrap();
    let error = AdmissionExecutor::new(1)
        .run(move || store.mark_once("pow", "proof", Duration::from_secs(601)))
        .await
        .unwrap_err();
    assert!(error.is::<AdmissionUnavailable>());
}

#[tokio::test]
async fn stalled_initialization_and_commands_are_typed_and_bounded() {
    for health in [false, true] {
        for init in [false, true] {
            let error = run_peer(init, health, None).await.unwrap_err();
            assert!(error.is::<AdmissionUnavailable>());
            assert_eq!(
                crate::routes::issue::sybil_verification_error(&error),
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "Sybil resistance temporarily unavailable".into()
                )
            );
        }
    }
}

#[tokio::test]
async fn confirmed_duplicate_is_rejection_and_command_error_is_unavailable() {
    run_peer(false, false, Some(b"+OK\r\n")).await.unwrap();
    let duplicate = run_peer(false, false, Some(b"$-1\r\n")).await.unwrap_err();
    assert!(!duplicate.is::<AdmissionUnavailable>());
    assert_eq!(
        crate::routes::issue::sybil_verification_error(&duplicate).0,
        axum::http::StatusCode::FORBIDDEN
    );
    let error = run_peer(false, false, Some(b"-ERR private backend details\r\n"))
        .await
        .unwrap_err();
    assert!(error.is::<AdmissionUnavailable>());
    run_peer(false, true, Some(b"+PONG\r\n")).await.unwrap();
}
