//! `galdra keyserver` — HTTP registry (Fulla-style) uploads and lookups.
//!
//! This is separate from `[keyservers]` HKP/WKD-style configuration (`galdra contact fetch --source keyserver`).

pub mod client;
pub mod fetch;
pub mod push;

use clap::Subcommand;
use fetch::{run_fetch, FetchArgs};
use galdra_core_host::config::Config;
use galdra_core_host::GaldraError;
use push::{run_push, PushArgs};

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum KeyserverCmd {
    Push(PushArgs),
    Fetch(FetchArgs),
}

pub fn run_keyserver(cmd: KeyserverCmd, config: &Config, quiet: bool) -> Result<(), GaldraError> {
    let registry_cfg = config.keyserver.as_ref();
    match cmd {
        KeyserverCmd::Push(args) => run_push(args, registry_cfg, quiet),
        KeyserverCmd::Fetch(args) => run_fetch(args, registry_cfg, quiet),
    }
}
