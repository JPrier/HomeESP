#![allow(clippy::unwrap_used, clippy::panic)]

use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_observatory-cli"))
}

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn validates_shipped_configs_and_rejects_bad_ones() {
    for f in ["configs/sim-site.yaml", "configs/site.example.yaml"] {
        let o = cli()
            .args(["config", "validate", "--file"])
            .arg(root().join(f))
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "{f}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(
        &bad,
        "schema_version: 1\nsite_id: home\nnodes: [{id: node-01, room: nowhere}]\n",
    )
    .unwrap();
    let o = cli()
        .args(["config", "validate", "--file"])
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("unknown room nowhere"));
}

#[test]
fn replay_fixture_yields_one_grouped_ap_incident() {
    let o = cli()
        .args(["replay", "--input"])
        .arg(root().join("tests/fixtures/scenario-ap-failure.jsonl"))
        .output()
        .unwrap();
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    let incidents: Vec<&str> = out.lines().filter(|l| l.starts_with("inc-")).collect();
    assert_eq!(incidents.len(), 1, "{out}");
    assert!(incidents[0].contains("ap-living"));
    assert!(
        incidents[0].contains("node-01")
            && incidents[0].contains("node-02")
            && incidents[0].contains("node-03")
    );
}

#[test]
fn decode_reports_rejection_instead_of_crashing() {
    let o = cli()
        .args(["decode", "--hex", "deadbeef"])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("REJECTED"));
}

#[test]
fn backup_create_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live.sqlite");
    drop(ho_storage::Store::open(&db).unwrap());
    let out = dir.path().join("b.sqlite");
    let o = cli()
        .args(["backup", "create", "--db"])
        .arg(&db)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = cli()
        .args(["backup", "verify", "--file"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("integrity: ok"));
    let again = cli()
        .args(["backup", "create", "--db"])
        .arg(&db)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        !again.status.success(),
        "never overwrites an existing backup"
    );
}
