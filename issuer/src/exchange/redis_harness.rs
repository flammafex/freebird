// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Isolated, durable Redis process for exchange acceptance tests.

use std::{
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

pub struct RedisHarness {
    child: Option<Child>,
    pub url: String,
    pub dir: PathBuf,
    port: u16,
}

impl RedisHarness {
    pub fn binary_available() -> bool {
        Command::new("redis-server")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    pub fn start() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        drop(listener);
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?.keep();
        let mut harness = Self {
            child: None,
            url: format!("redis://127.0.0.1:{port}/"),
            dir,
            port,
        };
        harness.spawn()?;
        Ok(harness)
    }

    fn spawn(&mut self) -> Result<(), String> {
        let child = Command::new("redis-server")
            .args([
                "--port",
                &self.port.to_string(),
                "--bind",
                "127.0.0.1",
                "--dir",
                self.dir.to_str().ok_or("non-UTF8 Redis directory")?,
                "--appendonly",
                "yes",
                "--appendfsync",
                "always",
                "--save",
                "",
                "--maxmemory-policy",
                "noeviction",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        self.child = Some(child);
        for _ in 0..250 {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return Ok(());
            }
            if self
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_some())
            {
                return Err("redis-server exited during startup".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        Err("redis-server did not become reachable".into())
    }

    pub fn restart(&mut self) -> Result<(), String> {
        self.stop();
        self.spawn()
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for RedisHarness {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
