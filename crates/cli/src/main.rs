//! observatory-cli: offline operator tooling (no network access except the explicit
//! serial provisioning helper).
//!
//!   observatory-cli config validate --file configs/site.yaml
//!   observatory-cli decode --hex 484f0100...
//!   observatory-cli sim run --scenario S02 --seed 42 [--export out.jsonl]
//!   observatory-cli sim all --seeds 5
//!   observatory-cli replay --input tests/fixtures/scenario-ap-failure.jsonl [--config site.yaml]
//!   observatory-cli backup create --db data/observatory.sqlite --output backup.sqlite
//!   observatory-cli backup verify --file backup.sqlite
//!   observatory-cli node provision --serial COM5 --node-id node-01 --secrets local/secrets/nodes.json

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ho_domain::SiteConfig;
use std::io::{BufRead, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "observatory-cli",
    version,
    about = "Home Observatory operator CLI"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Configuration tools.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Decode a wire frame (hex) and print it as JSON-ish debug output.
    Decode {
        #[arg(long)]
        hex: Option<String>,
        /// File containing one hex frame per line.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Deterministic simulator.
    Sim {
        #[command(subcommand)]
        cmd: SimCmd,
    },
    /// Replay a JSONL capture through the production engine (simulated clock).
    Replay {
        #[arg(long)]
        input: PathBuf,
        /// Site config used for replay (defaults to the embedded simulation site).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Backups using SQLite's online backup API.
    Backup {
        #[command(subcommand)]
        cmd: BackupCmd,
    },
    /// Node provisioning over USB serial (delegates to tools/esp.py, which handles
    /// the CH340 driver quirk and never prints secrets).
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Parse and validate (dry run). Exit code 1 when invalid.
    Validate {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum SimCmd {
    /// Run one scenario and print its report.
    Run {
        #[arg(long)]
        scenario: String,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Also export the generated frames as JSONL for `replay`.
        #[arg(long)]
        export: Option<PathBuf>,
    },
    /// Run every scenario over several seeds; exit 1 on any failure.
    All {
        #[arg(long, default_value_t = 3)]
        seeds: u64,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    Create {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    Provision {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        secrets: PathBuf,
        #[arg(long, default_value = "default")]
        profile: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Config {
            cmd: ConfigCmd::Validate { file },
        } => validate(&file),
        Cmd::Decode { hex, file } => decode(hex, file),
        Cmd::Sim { cmd } => sim(cmd),
        Cmd::Replay { input, config } => replay(&input, config.as_deref()),
        Cmd::Backup { cmd } => backup(cmd),
        Cmd::Node {
            cmd:
                NodeCmd::Provision {
                    serial,
                    node_id,
                    secrets,
                    profile,
                },
        } => provision(&serial, &node_id, &secrets, &profile),
    }
}

fn validate(file: &std::path::Path) -> Result<()> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let cfg: SiteConfig = match serde_yaml_parse(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("INVALID (parse): {e}");
            std::process::exit(1);
        }
    };
    let issues = cfg.validate();
    if issues.is_empty() {
        println!(
            "OK: {} — {} nodes, {} assets, {} rooms, {} probe targets, {} central checks, {} devices (location {})",
            file.display(),
            cfg.nodes.len(),
            cfg.assets.len(),
            cfg.rooms.len(),
            cfg.probe_targets.len(),
            cfg.central_checks.len(),
            cfg.devices.len(),
            if cfg.privacy.location_enabled { "enabled" } else { "disabled" }
        );
        Ok(())
    } else {
        for i in &issues {
            eprintln!("INVALID {}: {}", i.path, i.message);
        }
        std::process::exit(1);
    }
}

fn serde_yaml_parse(text: &str) -> Result<SiteConfig, String> {
    // Parse without validation so `validate` can print every semantic issue.
    serde_yaml::from_str(text).map_err(|e| e.to_string())
}

fn decode(hex_arg: Option<String>, file: Option<PathBuf>) -> Result<()> {
    let mut frames = Vec::new();
    if let Some(h) = hex_arg {
        frames.push(h);
    }
    if let Some(f) = file {
        let r = std::io::BufReader::new(std::fs::File::open(&f)?);
        for line in r.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                frames.push(line.trim().to_string());
            }
        }
    }
    if frames.is_empty() {
        bail!("provide --hex or --file");
    }
    for h in frames {
        let bytes = hex::decode(h.trim()).context("invalid hex")?;
        match ho_protocol::decode_frame(&bytes) {
            Ok(f) => {
                println!("{:?}", f.header);
                for r in f.records() {
                    println!("  {r:?}");
                }
            }
            Err(e) => println!("REJECTED: {e:?} ({})", e.label()),
        }
    }
    Ok(())
}

fn sim(cmd: SimCmd) -> Result<()> {
    match cmd {
        SimCmd::Run {
            scenario,
            seed,
            export,
        } => {
            if export.is_some() && scenario != "S02" && scenario != "healthy" {
                eprintln!("note: export records a fresh S02-style AP outage run");
            }
            let r = ho_simulator::scenarios::run(&scenario, seed)
                .with_context(|| format!("unknown scenario {scenario}"))?;
            println!("{}", serde_json::to_string_pretty(&r)?);
            if let Some(path) = export {
                let recs = record_ap_outage(seed);
                let mut f = std::fs::File::create(&path)?;
                for r in &recs {
                    writeln!(f, "{}", serde_json::to_string(r)?)?;
                }
                eprintln!("exported {} frames to {}", recs.len(), path.display());
            }
            if !r.passed() {
                std::process::exit(1);
            }
            Ok(())
        }
        SimCmd::All { seeds } => {
            let mut failed = 0;
            for id in ho_simulator::scenarios::ALL {
                let mut ok = 0;
                for seed in 1..=seeds {
                    if ho_simulator::scenarios::run(id, seed).is_some_and(|r| r.passed()) {
                        ok += 1;
                    } else {
                        failed += 1;
                    }
                }
                println!("{id}: {ok}/{seeds} seeds passed");
            }
            if failed > 0 {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

/// Produce a replayable capture of an AP outage (frames only; central checks are
/// not part of MQTT captures).
fn record_ap_outage(seed: u64) -> Vec<ho_simulator::Recorded> {
    let mut w = ho_simulator::World::new(ho_simulator::sim_config(), seed);
    w.h.record = true;
    w.run(120_000);
    w.net.ap_down = Some("ap-living".into());
    w.roam("node-02", "ap-office");
    w.roam("node-03", "ap-office");
    w.run(90_000);
    w.h.recorded.clone()
}

fn replay(input: &std::path::Path, config: Option<&std::path::Path>) -> Result<()> {
    let cfg = match config {
        Some(p) => SiteConfig::from_yaml_str(&std::fs::read_to_string(p)?)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        None => ho_simulator::sim_config(),
    };
    let mut h = ho_simulator::Harness::new(cfg);
    let r = std::io::BufReader::new(
        std::fs::File::open(input).with_context(|| format!("opening {}", input.display()))?,
    );
    let mut next_tick: Option<i64> = None;
    let mut n = 0u64;
    for line in r.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: ho_simulator::Recorded =
            serde_json::from_str(&line).context("bad JSONL record")?;
        let bytes = ho_simulator::hex_decode(&rec.hex).context("bad hex")?;
        // Simulated clock: tick every second of capture time.
        let mut t = next_tick.unwrap_or(rec.received_at);
        while t <= rec.received_at {
            h.input(t, ho_logic::engine::Input::Tick(t));
            t += 1000;
        }
        next_tick = Some(t);
        h.ingest(&rec.topic, &bytes, rec.received_at);
        n += 1;
    }
    // No ticks past the end of the capture: silence after it is not evidence.
    println!(
        "replayed {n} frames (accepted {}, duplicates {}, rejected {:?})",
        h.accepted, h.duplicates, h.rejected
    );
    for i in h.incidents() {
        println!(
            "{} [{:?}] {:?} {} — {} | affected {:?} | confidence {:?}",
            i.id,
            i.status,
            i.severity,
            i.hypothesis.title,
            i.hypothesis.cause,
            i.hypothesis.affected_nodes,
            i.hypothesis.confidence
        );
    }
    Ok(())
}

fn backup(cmd: BackupCmd) -> Result<()> {
    match cmd {
        BackupCmd::Create { db, output } => {
            if output.exists() {
                bail!("{} already exists; refusing to overwrite", output.display());
            }
            let s = ho_storage::Store::open_readonly(&db)
                .with_context(|| format!("opening {}", db.display()))?;
            s.backup_to(&output)?;
            let b = ho_storage::Store::open_readonly(&output)?;
            println!(
                "backup written: {} (integrity: {}, {})",
                output.display(),
                b.integrity_check()?,
                b.counts()?
            );
            Ok(())
        }
        BackupCmd::Verify { file } => {
            let b = ho_storage::Store::open_readonly(&file)?;
            let ic = b.integrity_check()?;
            println!(
                "integrity: {ic}; schema v{}; {}",
                b.schema_version()?,
                b.counts()?
            );
            if ic != "ok" {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

fn provision(serial: &str, node: &str, secrets: &std::path::Path, profile: &str) -> Result<()> {
    if !ho_domain::valid_id(node) {
        bail!("invalid node id {node}");
    }
    let tool = std::env::current_exe()?
        .ancestors()
        .map(|p| p.join("tools").join("esp.py"))
        .find(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("tools/esp.py"));
    eprintln!(
        "profile '{profile}' is applied by the server as desired config after the node connects"
    );
    let python = if cfg!(windows) { "python" } else { "python3" };
    let st = std::process::Command::new(python)
        .arg(&tool)
        .args(["provision", "--port", serial, "--node", node, "--secrets"])
        .arg(secrets)
        .status()
        .with_context(|| format!("running {}", tool.display()))?;
    if !st.success() {
        bail!("provisioning failed");
    }
    Ok(())
}
