//! observatory-server: the central Home Observatory service.

use anyhow::{bail, Context, Result};
use clap::Parser;
use ho_domain::SiteConfig;
use ho_logic::engine::Engine;
use ho_server::{api, auth, jobs, now_ms, writer, Metrics, Shared};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "observatory-server",
    version,
    about = "Home Observatory central service"
)]
struct Args {
    /// Site configuration (YAML).
    #[arg(long, default_value = "configs/site.yaml")]
    config: PathBuf,
    /// JSON structured logs.
    #[arg(long)]
    log_json: bool,
    /// Allow running without API tokens (only when bound to loopback).
    #[arg(long)]
    dev_no_auth: bool,
    /// Demo mode: synthetic nodes from the deterministic simulator, MQTT and all real
    /// network probing disabled. Safe on any network; data is clearly synthetic.
    #[arg(long)]
    simulate: bool,
    #[arg(long, default_value_t = 42)]
    seed: u64,
}

fn read_secret(path: &str) -> Result<String> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading secret file {path}"))?;
    Ok(s.trim().to_string())
}

/// Parse `node-id=<hex>` lines.
fn read_echo_keys(path: &str) -> Result<HashMap<String, Vec<u8>>> {
    let mut m = HashMap::new();
    for line in std::fs::read_to_string(path)
        .with_context(|| format!("reading {path}"))?
        .lines()
    {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .context("echo keys: expected node=hex")?;
        let key = hex::decode(v.trim()).context("echo keys: bad hex")?;
        if key.len() < 16 {
            bail!("echo key for {k} too short");
        }
        m.insert(k.trim().to_string(), key);
    }
    Ok(m)
}

fn is_loopback(bind: &str) -> bool {
    bind.starts_with("127.") || bind.starts_with("[::1]") || bind.starts_with("localhost:")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // One process-wide TLS crypto provider (ring), shared by MQTT and HTTPS clients.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if args.log_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let mut cfg = SiteConfig::from_yaml_str(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
    if args.simulate {
        cfg.mqtt.enabled = false;
        cfg.server.echo_bind = None;
        cfg.home_assistant.enabled = false;
        cfg.watchdog = None;
    }
    let base = args.config.parent().unwrap_or(Path::new("."));
    let resolve = |p: &str| -> String {
        let pb = PathBuf::from(p);
        if pb.is_absolute() {
            p.to_string()
        } else {
            base.join(pb).to_string_lossy().into_owned()
        }
    };

    // Tokens: required unless loopback dev mode.
    let tokens = match &cfg.server.api_tokens_file {
        Some(f) => auth::Tokens::load(Path::new(&resolve(f))).map_err(|e| anyhow::anyhow!(e))?,
        None if args.dev_no_auth && is_loopback(&cfg.server.bind) => {
            tracing::warn!("API authentication DISABLED (dev mode, loopback bind only)");
            auth::Tokens::dev_open()
        }
        None => bail!("server.api_tokens_file is required (or --dev-no-auth with a loopback bind)"),
    };
    let mqtt_password = match &cfg.mqtt.password_file {
        Some(f) => Some(read_secret(&resolve(f))?),
        None => None,
    };
    let echo_keys = match &cfg.server.echo_keys_file {
        Some(f) => read_echo_keys(&resolve(f))?,
        None => HashMap::new(),
    };
    let mut notifier_tokens = BTreeMap::new();
    for n in &cfg.notifications.notifiers {
        if let Some(f) = &n.token_file {
            notifier_tokens.insert(n.id.clone(), read_secret(&resolve(f))?);
        }
    }

    // Storage + revisioned config (monotonic desired-config revision).
    let db_path = PathBuf::from(resolve(&cfg.server.database_path));
    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let mut store = ho_storage::Store::open(&db_path).context("opening database")?;
    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(text.as_bytes()));
    let revision = match store.active_config_revision()? {
        Some((rev, s)) if s == sha => rev,
        _ => store.save_config_revision(now_ms(), "startup", &sha, &text)?,
    };
    let counter: u64 = store
        .kv_get("incident_counter")?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    tracing::info!(revision, incident_counter = counter, db = %db_path.display(), "storage ready");
    let writer = writer::spawn(store, cfg.server.ingest_queue);

    let (events, _) = tokio::sync::broadcast::channel(1024);
    let mut engine = Engine::with_incident_counter(cfg.clone(), counter);
    // Restore last-seen times so nodes that went silent before a restart are still
    // detected as missing (S15).
    for row in ho_storage::Store::open_readonly(&db_path)
        .and_then(|r| r.nodes())
        .unwrap_or_default()
    {
        if let (Some(id), Some(t)) = (row["id"].as_str(), row["last_seen"].as_i64()) {
            engine.seed_last_seen(id, t);
        }
    }
    let snapshot = Arc::new(engine.snapshot());
    let dashboard_dir = cfg
        .server
        .dashboard_dir
        .as_ref()
        .map(|d| PathBuf::from(resolve(d)))
        .filter(|d| d.join("index.html").exists());
    let app = Arc::new(Shared {
        cfg: cfg.clone(),
        // Simulate mode overrides parts of the config in memory, so API config writes
        // (which compare against the running config) are disabled there.
        config_path: (!args.simulate).then(|| args.config.clone()),
        db_path,
        engine: Mutex::new(engine),
        snapshot: RwLock::new(snapshot),
        writer,
        metrics: Metrics::default(),
        events,
        tokens,
        mqtt: RwLock::new(None),
        mqtt_connected: AtomicBool::new(false),
        started_at: now_ms(),
        desired_revision: AtomicU64::new(u64::try_from(revision).unwrap_or(0)),
        server_seq: AtomicU64::new(0),
        echo_stats: Arc::new(Mutex::new((0, 0))),
        ingest: Mutex::new(Default::default()),
        dashboard_dir,
        notifier_tokens,
        watchdog_ok: Mutex::new(None),
    });

    let cancel = CancellationToken::new();
    let mut tasks = Vec::new();
    if cfg.mqtt.enabled {
        let (client, el) =
            jobs::mqtt_client(&cfg, mqtt_password).map_err(|e| anyhow::anyhow!(e))?;
        if let Ok(mut m) = app.mqtt.write() {
            *m = Some(client.clone());
        }
        tasks.push(tokio::spawn(jobs::run_mqtt(
            app.clone(),
            client,
            el,
            cancel.clone(),
        )));
    }
    tasks.push(tokio::spawn(jobs::run_ticks(app.clone(), cancel.clone())));
    tasks.push(tokio::spawn(jobs::run_outbox(app.clone(), cancel.clone())));
    if args.simulate {
        tasks.push(tokio::spawn(ho_server::sim::run(
            app.clone(),
            args.seed,
            cancel.clone(),
        )));
    } else {
        tasks.push(tokio::spawn(jobs::run_central(app.clone(), cancel.clone())));
    }
    tasks.push(tokio::spawn(jobs::run_echo(
        app.clone(),
        echo_keys,
        cancel.clone(),
    )));
    tasks.push(tokio::spawn(jobs::run_ha(app.clone(), cancel.clone())));
    tasks.push(tokio::spawn(jobs::run_maintenance(
        app.clone(),
        cancel.clone(),
    )));
    tasks.push(tokio::spawn(jobs::run_watchdog(
        app.clone(),
        cancel.clone(),
    )));

    let listener = tokio::net::TcpListener::bind(&cfg.server.bind)
        .await
        .with_context(|| format!("binding {}", cfg.server.bind))?;
    tracing::info!(bind = %cfg.server.bind, "http api listening");
    let c2 = cancel.clone();
    axum::serve(listener, api::router(app.clone()))
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown requested");
            c2.cancel();
        })
        .await?;
    cancel.cancel();
    for t in tasks {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), t).await;
    }
    drop(app);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await; // let the writer checkpoint
    Ok(())
}
