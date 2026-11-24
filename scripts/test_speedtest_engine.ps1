param([switch]$Online)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskHarness = Join-Path $taskRoot '.tmp/speedtest-engine-tests'
New-Item -ItemType Directory -Force -Path $taskHarness | Out-Null
@'
[package]
name = "labrelay-speedtest-engine-tests"
version = "0.1.0"
edition = "2021"
[lib]
path = "../../labrelay/src/speedtest.rs"
[dependencies]
anyhow = "1"
futures-util = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", default-features = false, features = ["macros", "rt-multi-thread", "net", "io-util", "time", "sync"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream"] }
'@ | Set-Content -LiteralPath (Join-Path $taskHarness 'Cargo.toml') -Encoding utf8
# Preserve the candidate's dependency versions when testing on Windows, where
# the full Unix daemon cannot be linked. The exact production module is loaded.
Copy-Item -LiteralPath (Join-Path $taskRoot 'labrelay/Cargo.lock') -Destination (Join-Path $taskHarness 'Cargo.lock') -Force
$taskArgs = @('test', '--manifest-path', (Join-Path $taskHarness 'Cargo.toml'), '--lib')
if (-not $Online) { $taskArgs += '--offline' }
& cargo @taskArgs
if ($LASTEXITCODE -ne 0) { throw "Speedtest engine fixture tests failed ($LASTEXITCODE)" }
