// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use anyhow::Result;
use freebird_common::logging;
use freebird_issuer::{config::Config, startup::Application};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Init Logging
    logging::init("info,axum=info,tower_http=info");

    // 2. Load Config
    let config = Config::from_env()?;

    // 3. Build Application
    let app = Application::build(config).await?;

    // 4. Run
    app.run().await
}