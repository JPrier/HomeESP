//! Print a scenario report (debug aid): cargo run --example inspect -- S16 [seed]
use ho_simulator::scenarios;
fn main() {
    let id = std::env::args().nth(1).unwrap_or_else(|| "S01".into());
    let seed = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);
    if let Some(r) = scenarios::run(&id, seed) {
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    }
}
