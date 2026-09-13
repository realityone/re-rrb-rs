//! Async orchestration: capture tasks per source port, a single inject task
//! owning the TAP, and signal-driven shutdown.
use crate::{
    config::{Mode, Settings},
    packet::PacketSocket,
    proto::{
        self, COUNTER_NAMES, Counter, Filter,
        parse::{self},
    },
    relay::{self, Limiter},
    tap,
};
use anyhow::Result;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, error, info, trace, warn};

/// Bounded channel between capture and inject tasks: under a burst, excess
/// frames are dropped by the rate limiter anyway, so deep buffering would
/// only add latency.
const QUEUE_DEPTH: usize = 64;

/// Shared daemon statistics, indexed by `Counter` discriminant. Locking is
/// uncontended in practice (a handful of events per roam).
pub type Counters = Arc<Mutex<[u64; COUNTER_NAMES.len()]>>;

fn bump(counters: &Counters, c: Counter) {
    counters.lock().unwrap()[c as usize] += 1;
}

fn log_counters(counters: &Counters) {
    let c = counters.lock().unwrap();
    let line = COUNTER_NAMES
        .iter()
        .zip(c.iter())
        .filter(|(_, v)| **v > 0)
        .map(|(name, v)| format!("{name}={v}"))
        .collect::<Vec<_>>()
        .join(" ");
    info!(counters = %line, "daemon counters");
}

/// Seconds on a monotonic clock with an arbitrary epoch; only equality and
/// increments matter to the limiter.
fn monotonic_secs(start: &Instant) -> u64 {
    start.elapsed().as_secs()
}

/// Capture loop for one source port: receive, validate, hand untagged frames
/// to the inject task (forward) or just count them (observe).
async fn capture(
    sock: PacketSocket,
    filter: Filter,
    forward: Option<mpsc::Sender<Vec<u8>>>,
    counters: Counters,
) {
    let mut buf = vec![0u8; proto::MAX_FRAME];
    loop {
        match sock.recv(&mut buf).await {
            Ok((n, vlan)) => {
                bump(&counters, Counter::Seen);
                let frame = &buf[..n];
                match parse::classify(&frame, vlan, &filter) {
                    Ok(m) => {
                        bump(&counters, Counter::Matched);
                        bump(&counters, relay::kind_counter(m.kind));
                        // Per-frame detail at debug: RRB frames are rare (a
                        // handful per roam), so this stays cheap. `client`
                        // is the roaming device's MAC (S1KH-ID TLV).
                        debug!(
                            source = sock.name,
                            kind = relay::kind_name(m.kind),
                            from = relay::mac_string(frame[6..12].try_into().unwrap()),
                            to = relay::mac_string(frame[0..6].try_into().unwrap()),
                            client = m.s1kh.map(|s| relay::mac_string(&s)),
                            len = n,
                            "rrb frame matched"
                        );
                        match &forward {
                            Some(tx) => {
                                if tx.send(relay::untag(frame, vlan)).await.is_err() {
                                    return; // inject task gone: shutting down
                                }
                            }
                            None => bump(&counters, Counter::Observed),
                        }
                    }
                    Err(reason) => {
                        bump(&counters, reason);
                        // Rejections at trace: on a noisy segment these are
                        // counted, not narrated.
                        trace!(
                            source = sock.name,
                            reason = COUNTER_NAMES[reason as usize],
                            len = n,
                            "rrb frame rejected"
                        );
                    }
                }
            }
            Err(e) => {
                error!(source = sock.name, "capture failed: {e}");
                return;
            }
        }
    }
}

/// Owns the TAP: applies the rate limiter and injects frames. Exits when
/// every capture task has hung up (daemon shutdown).
async fn inject(
    tap: tap::RelayTap,
    mut rx: mpsc::Receiver<Vec<u8>>,
    counters: Counters,
    packets_per_second: u32,
    start: Instant,
) {
    let mut limiter = Limiter::new(packets_per_second);
    while let Some(frame) = rx.recv().await {
        match limiter.admit(monotonic_secs(&start)) {
            Ok(()) => match tap.inject(&frame).await {
                Ok(()) => bump(&counters, Counter::Injected),
                Err(e) => {
                    bump(&counters, Counter::InjectError);
                    warn!("TAP inject failed: {e}");
                }
            },
            Err(reason) => bump(&counters, reason),
        }
    }
}

pub async fn run(config_path: &str) -> Result<()> {
    let settings = Settings::load(config_path)?;
    let filter = settings.filter()?;
    let counters: Counters = Arc::new(Mutex::new([0; COUNTER_NAMES.len()]));
    let start = Instant::now();

    // Forward mode: the TAP and its mirred rule exist only while this
    // process does. Observe mode never creates them at all.
    let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
    let mut tasks = JoinSet::new();
    if settings.mode == Mode::Forward {
        let relay = tap::create_relay(&settings.tap, &settings.target, settings.pref).await?;
        info!(
            tap = relay.name,
            ifindex = relay.ifindex,
            target = settings.target,
            "relay TAP up, mirred ingress installed"
        );
        let c = counters.clone();
        let pps = settings.limits.packets_per_second;
        tasks.spawn(async move { inject(relay, rx, c, pps, start).await });
    } else {
        drop(rx);
    }

    for name in &settings.sources {
        let sock = PacketSocket::open(name)?;
        info!(source = name, "capturing");
        let tx = (settings.mode == Mode::Forward).then(|| tx.clone());
        tasks.spawn(capture(sock, filter.clone(), tx, counters.clone()));
    }
    drop(tx); // the inject task ends when every capture task ends

    // Wait for SIGINT/SIGTERM.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = sigint.recv() => info!("SIGINT"),
        _ = sigterm.recv() => info!("SIGTERM"),
    }

    // Kernel-side cross-check must be read BEFORE shutdown: the TAP (and its
    // action) disappears as soon as the inject task drops it.
    if settings.mode == Mode::Forward {
        match tap::action_stats(&settings.tap).await {
            Ok(s) => info!("kernel mirred action:\n{s}"),
            Err(e) => warn!("kernel action stats unavailable: {e}"),
        }
    }
    tasks.shutdown().await;
    info!("daemon counters:");
    log_counters(&counters);
    Ok(())
}
