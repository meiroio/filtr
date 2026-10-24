//! Single-threaded inspection microbenchmark; excludes networking and SBOM compilation.
use filtr::{
    policy::{Catalog, Policy},
    sbom,
};
use std::{hint::black_box, time::Instant};

fn main() -> anyhow::Result<()> {
    let iterations: u32 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "100000".into())
        .parse()?;
    anyhow::ensure!(iterations > 0, "iterations must be positive");
    let policy = Policy::compile(
        sbom::parse(include_bytes!("sbom.cdx.json"))?,
        &Catalog::bundled()?,
    )?;
    let clean = vec![b'a'; 1024];
    let large = vec![b'a'; 64 * 1024];
    let escaped = "%41".repeat(341).into_bytes();
    for (name, bytes, blocked) in [
        ("clean 1 KiB", clean.as_slice(), false),
        ("clean 64 KiB", large.as_slice(), false),
        ("percent-encoded 1 KiB", escaped.as_slice(), false),
        ("encoded lookup", b"%2524%257Bjndi:x%257D".as_slice(), true),
    ] {
        assert_eq!(policy.inspect_bytes(bytes, false).is_some(), blocked);
        let started = Instant::now();
        for _ in 0..iterations {
            black_box(policy.inspect_bytes(black_box(bytes), false));
        }
        let elapsed = started.elapsed().as_secs_f64();
        println!(
            "{name}: {:.0} ns/inspection, {:.1} MiB/s ({iterations} iterations)",
            elapsed * 1e9 / f64::from(iterations),
            bytes.len() as f64 * f64::from(iterations) / elapsed / 1_048_576.0
        );
    }
    Ok(())
}
