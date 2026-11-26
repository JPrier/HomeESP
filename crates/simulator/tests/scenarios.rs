//! Mandatory fault scenarios S01–S17 run against the production engine.
#![allow(clippy::unwrap_used, clippy::panic)]

use ho_simulator::scenarios;

fn assert_scenario(id: &str) {
    let r = scenarios::run(id, 42).unwrap();
    let failed: Vec<_> = r.checks.iter().filter(|c| !c.1).collect();
    assert!(failed.is_empty(), "{id} {} failed checks: {failed:?}\nmetrics: {:?}\nnotes: {:?}", r.title, r.metrics, r.notes);
}

#[test]
fn s01_healthy_day() {
    assert_scenario("S01");
}
#[test]
fn s02_ap_outage() {
    assert_scenario("S02");
}
#[test]
fn s03_radio_disabled() {
    assert_scenario("S03");
}
#[test]
fn s04_node_missing() {
    assert_scenario("S04");
}
#[test]
fn s05_dns_down() {
    assert_scenario("S05");
}
#[test]
fn s06_wireless_dns() {
    assert_scenario("S06");
}
#[test]
fn s07_congestion() {
    assert_scenario("S07");
}
#[test]
fn s08_wan() {
    assert_scenario("S08");
}
#[test]
fn s09_broker_outage() {
    assert_scenario("S09");
}
#[test]
fn s10_reboot_duplicates() {
    assert_scenario("S10");
}
#[test]
fn s11_phone_left_behind() {
    assert_scenario("S11");
}
#[test]
fn s12_ambiguous_boundary() {
    assert_scenario("S12");
}
#[test]
fn s13_consent_revoked() {
    assert_scenario("S13");
}
#[test]
fn s14_malformed() {
    assert_scenario("S14");
}
#[test]
fn s15_restart() {
    assert_scenario("S15");
}
#[test]
fn s16_stress() {
    assert_scenario("S16");
}
#[test]
fn s17_experiments_disabled() {
    assert_scenario("S17");
}

#[test]
fn determinism_same_seed_same_outcome() {
    let a = scenarios::run("S02", 7).unwrap();
    let b = scenarios::run("S02", 7).unwrap();
    assert_eq!(format!("{:?}", a.checks), format!("{:?}", b.checks));
    assert_eq!(a.metrics, b.metrics);
}
