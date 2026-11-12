//! The running enforcer: watch the API, and on every change write the node's table again if its rules changed.
//!
//! It fails loudly, not open: a script `nft` refuses is logged with nft's reason, retried, and after
//! [`MAX_FAILURES`] in a row the process exits non-zero, for its supervisor to restart and its operator to see. The
//! table last applied stays in force meanwhile.

use crate::{compile, kube as convert, nft};
use anyhow::{Context, anyhow};
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client, Resource};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Consecutive failed applies before the process gives up.
pub const MAX_FAILURES: u32 = 5;

/// Changes arriving within this window are applied together.
const SETTLE: Duration = Duration::from_millis(200);

pub struct Options {
    pub node: String,
    pub table: String,
    pub nft: String,
    /// Apply once the watches are in step, then exit.
    pub once: bool,
}

pub async fn run(client: Client, opts: Options) -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let namespaces = watch::<Namespace>(Api::all(client.clone()), tx.clone());
    let pods = watch::<Pod>(Api::all(client.clone()), tx.clone());
    let policies = watch::<NetworkPolicy>(Api::all(client), tx);
    for (what, ready) in [
        ("namespaces", namespaces.wait_until_ready().await),
        ("pods", pods.wait_until_ready().await),
        ("network policies", policies.wait_until_ready().await),
    ] {
        ready.map_err(|e| anyhow!("the watch of {what} ended before it was in step: {e}"))?;
    }
    info!(node = %opts.node, table = %opts.table, "watches in step; enforcing");
    let dual_stack = pods
        .state()
        .iter()
        .filter(|p| {
            p.status
                .as_ref()
                .and_then(|s| s.pod_ips.as_ref())
                .is_some_and(|ips| ips.iter().any(|i| i.ip.contains(':')))
        })
        .count();
    if dual_stack > 0 {
        warn!(
            pods = dual_stack,
            "pods with IPv6 addresses: their IPv6 traffic is not enforced, only IPv4"
        );
    }

    let mut last: Option<String> = None;
    let mut failures = 0u32;
    loop {
        let cluster = convert::cluster(
            namespaces.state().iter().map(|o| o.as_ref()),
            pods.state().iter().map(|o| o.as_ref()),
            policies.state().iter().map(|o| o.as_ref()),
        );
        let rules = compile::compile(&cluster, &opts.node);
        let script = nft::script(&opts.table, &rules);
        if last.as_deref() != Some(script.as_str()) {
            match apply(&opts.nft, &script).await {
                Ok(()) => {
                    failures = 0;
                    info!(
                        ingress_isolated = rules.ingress_isolated.len(),
                        egress_isolated = rules.egress_isolated.len(),
                        ingress_entries = rules.ingress.len(),
                        egress_entries = rules.egress.len(),
                        "table written"
                    );
                    last = Some(script);
                }
                Err(e) => {
                    failures += 1;
                    error!(failures, "the table could not be written: {e:#}");
                    if failures >= MAX_FAILURES {
                        return Err(e.context(format!("{MAX_FAILURES} failed writes in a row")));
                    }
                    tokio::time::sleep(Duration::from_secs(u64::from(failures))).await;
                    continue;
                }
            }
        }
        if opts.once {
            return Ok(());
        }
        if rx.recv().await.is_none() {
            return Err(anyhow!("every watch has ended"));
        }
        tokio::time::sleep(SETTLE).await;
        while rx.try_recv().is_ok() {}
    }
}

/// A store of `K`, kept by a watch that says on `tx` when it changes. The watch retries with backoff on errors, which
/// it logs, so a store goes stale while the API cannot be reached, rather than empty.
fn watch<K>(api: Api<K>, tx: mpsc::Sender<()>) -> Store<K>
where
    K: Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + k8s_openapi::serde::de::DeserializeOwned
        + 'static,
{
    let (store, writer) = reflector::store();
    let stream =
        reflector::reflector(writer, watcher(api, watcher::Config::default())).default_backoff();
    tokio::spawn(async move {
        let mut stream = std::pin::pin!(stream);
        while let Some(ev) = stream.next().await {
            match ev {
                Ok(_) => {
                    let _ = tx.try_send(());
                }
                Err(e) => warn!("watch error, retrying: {e}"),
            }
        }
        debug!("watch ended");
    });
    store
}

/// Gives the script to `nft -f -`, which applies it as one transaction.
pub async fn apply(nft: &str, script: &str) -> anyhow::Result<()> {
    let mut child = Command::new(nft)
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("running {nft}"))?;
    let mut stdin = child.stdin.take().context("nft's stdin")?;
    stdin.write_all(script.as_bytes()).await?;
    drop(stdin);
    let out = child.wait_with_output().await?;
    if out.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "{nft} refused the script ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}
