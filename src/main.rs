use anyhow::Context;
use clap::Parser;
use kube_nftpolicy::ranges::Range;
use kube_nftpolicy::run::{Options, run};
use kube_nftpolicy::{compile, nft};

/// Enforce Kubernetes NetworkPolicy for this node's pods in an nftables table of the `ip` family.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// This node's name, as Kubernetes knows it: its pods are the ones enforced here.
    #[arg(long, env = "NODE_NAME", required_unless_present = "remove")]
    node_name: Option<String>,
    /// A kubeconfig to reach the API with. Without it, the usual places: KUBECONFIG, ~/.kube/config, or in-cluster.
    #[arg(long)]
    kubeconfig: Option<std::path::PathBuf>,
    /// The node's pod address range(s), from which its pods get their addresses. Within them, an address that is no
    /// pod the enforcer knows is refused, so that a new pod is isolated before the API reports it. Without it, the
    /// node's `spec.podCIDRs`; with neither, a new pod runs unenforced for a moment, and a warning says so.
    #[arg(long = "pod-cidr", env = "POD_CIDR", value_delimiter = ',')]
    pod_cidrs: Vec<String>,
    /// The nftables table it owns, in the `ip` family.
    #[arg(long, default_value = nft::DEFAULT_TABLE)]
    table: String,
    /// The nft binary.
    #[arg(long, default_value = "nft")]
    nft: String,
    /// Write the table once the watches are in step, then exit.
    #[arg(long)]
    once: bool,
    /// Print the script this node would apply, and exit without applying it.
    #[arg(long)]
    print: bool,
    /// Delete the table and exit: what uninstalling it needs, since the table outlives the process. A table left
    /// behind keeps enforcing a stale picture, and refuses every new pod in the node's pod ranges.
    #[arg(long, conflicts_with_all = ["print", "once"])]
    remove: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    if args.remove {
        // Created first, so the delete succeeds when there is no table.
        let script = format!("add table ip {t}\ndelete table ip {t}\n", t = args.table);
        kube_nftpolicy::run::apply(&args.nft, &script).await?;
        tracing::info!(table = %args.table, "table removed");
        return Ok(());
    }
    let node_name = args.node_name.expect("required unless --remove");
    let config = match &args.kubeconfig {
        Some(path) => {
            let kc = kube::config::Kubeconfig::read_from(path)
                .with_context(|| format!("reading {}", path.display()))?;
            kube::Config::from_custom_kubeconfig(kc, &Default::default()).await?
        }
        None => kube::Config::infer().await?,
    };
    let client = kube::Client::try_from(config)?;
    let pod_ranges = pod_ranges(&client, &node_name, &args.pod_cidrs).await?;
    if args.print {
        let cluster = snapshot(client).await?;
        print!(
            "{}",
            nft::script(
                &args.table,
                &compile::compile(&cluster, &node_name, &pod_ranges)
            )
        );
        return Ok(());
    }
    run(
        client,
        Options {
            node: node_name,
            pod_ranges,
            table: args.table,
            nft: args.nft,
            once: args.once,
        },
    )
    .await
}

/// The node's pod ranges: as given, or else from the Node object's `spec.podCIDRs`. IPv6 ranges are passed over.
async fn pod_ranges(
    client: &kube::Client,
    node: &str,
    given: &[String],
) -> anyhow::Result<Vec<Range>> {
    let mut cidrs: Vec<String> = given
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cidrs.is_empty() {
        let n = kube::Api::<k8s_openapi::api::core::v1::Node>::all(client.clone())
            .get(node)
            .await?;
        let spec = n.spec.unwrap_or_default();
        cidrs = spec.pod_cidrs.unwrap_or_default();
        cidrs.extend(spec.pod_cidr);
    }
    let mut out = Vec::new();
    for c in &cidrs {
        match kube_nftpolicy::kube::cidr(c) {
            Some(c) => {
                let (start, end) = c.bounds();
                out.push(Range { start, end });
            }
            None if c.contains(':') => {}
            None => anyhow::bail!("not a pod range: {c}"),
        }
    }
    if out.is_empty() {
        tracing::warn!(
            "no IPv4 pod range for this node (--pod-cidr, or the node's spec.podCIDRs): a new pod runs unenforced until its address is seen"
        );
    }
    Ok(out)
}

/// The cluster as it is now, listed once.
async fn snapshot(client: kube::Client) -> anyhow::Result<kube_nftpolicy::model::Cluster> {
    use k8s_openapi::api::{
        core::v1::{Namespace, Pod},
        networking::v1::NetworkPolicy,
    };
    use kube::api::{Api, ListParams};
    let lp = ListParams::default();
    let ns = Api::<Namespace>::all(client.clone()).list(&lp).await?;
    let pods = Api::<Pod>::all(client.clone()).list(&lp).await?;
    let nps = Api::<NetworkPolicy>::all(client).list(&lp).await?;
    Ok(kube_nftpolicy::kube::cluster(
        &ns.items,
        &pods.items,
        &nps.items,
    ))
}
