//! Run every scenario across many seeds and report failures (flakiness check).
use ho_simulator::scenarios;
fn main() {
    let n: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let mut fails = 0;
    for id in scenarios::ALL {
        let mut bad = Vec::new();
        for seed in 1..=n {
            if let Some(r) = scenarios::run(id, seed) {
                if !r.passed() {
                    bad.push((
                        seed,
                        r.checks
                            .iter()
                            .filter(|c| !c.1)
                            .map(|c| c.0.clone())
                            .collect::<Vec<_>>(),
                    ));
                }
            }
        }
        fails += bad.len();
        println!(
            "{id}: {}/{} seeds pass {:?}",
            n as usize - bad.len(),
            n,
            bad.first()
        );
    }
    std::process::exit(i32::from(fails > 0));
}
