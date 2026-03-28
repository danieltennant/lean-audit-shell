/// Startup latency benchmark.
///
/// Measures the wall-clock time from process start to first output for two
/// modes:
///   - `leash --version`  — minimal path (no config load, no PTY)
///   - `leash -c "true"`  — full path (config load + ZshBackend + PTY)
///
/// Target: both paths complete in < 150 ms on a warmed macOS machine.
use criterion::{criterion_group, criterion_main, Criterion};
use std::process::Command;

fn bench_version(c: &mut Criterion) {
    let bin = env!("CARGO_BIN_EXE_leash");
    c.bench_function("startup: --version", |b| {
        b.iter(|| {
            Command::new(bin)
                .arg("--version")
                .output()
                .expect("failed to spawn leash");
        });
    });
}

fn bench_c_true(c: &mut Criterion) {
    let bin = env!("CARGO_BIN_EXE_leash");
    c.bench_function("startup: -c true", |b| {
        b.iter(|| {
            Command::new(bin)
                .args(["-c", "true"])
                .output()
                .expect("failed to spawn leash");
        });
    });
}

criterion_group!(benches, bench_version, bench_c_true);
criterion_main!(benches);
