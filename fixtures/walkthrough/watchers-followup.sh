#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?Use a fresh disposable database}"
repo=$(realpath -- "$(dirname -- "$0")/../..")
platform=$(realpath -- "$repo/../../..")
BILIBI_ENV=development cargo run --locked --manifest-path "$platform/Cargo.toml" -p bilibi-people-walkthrough -- rules-source
cargo run --locked --manifest-path "$platform/Cargo.toml" -p bilibi-web --example watchers-domains-walkthrough -- people
