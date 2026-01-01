// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Build script to sync the admin UI from the shared admin-ui directory
//!
//! This ensures the unified admin UI is embedded in the verifier binary.

use std::fs;
use std::path::Path;

fn main() {
    let src = Path::new("../admin-ui/index.html");
    let dst = Path::new("src/admin_ui/index.html");

    // Create directory if needed
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).ok();
    }

    // Copy file if source exists
    if src.exists() {
        match fs::copy(src, dst) {
            Ok(_) => println!("cargo:warning=Copied admin UI from ../admin-ui/index.html"),
            Err(e) => println!("cargo:warning=Failed to copy admin UI: {}", e),
        }
    } else {
        println!("cargo:warning=Admin UI source not found at ../admin-ui/index.html");
    }

    // Tell Cargo to rerun this script if the source file changes
    println!("cargo:rerun-if-changed=../admin-ui/index.html");
}
