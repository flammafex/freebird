// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use freebird_common::logging;
use freebird_common::metrics;
use freebird_verifier::{
    application::shutdown_signal, application::Application, settings::Settings,
};
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init("debug");
    metrics::register_metrics();

    let settings = Settings::from_env()?;
    let application = Application::build(settings).await?;

    // BIND_ADDR is intentionally the final startup environment read.
    let addr = Settings::bind_addr()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "Freebird verifier listening on http://{}",
        listener.local_addr()?
    );

    application.serve(listener, shutdown_signal()).await
}
