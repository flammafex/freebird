// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::Result;

#[path = "public_bearer_exchange/support.rs"]
mod support;
#[path = "public_bearer_exchange/v7_enabled.rs"]
mod v7_enabled_support;

#[tokio::test]
async fn v7_enabled_runtime_proves_cutover_and_readiness() -> Result<()> {
    v7_enabled_support::v7_enabled_runtime_cutover_characterization().await
}
