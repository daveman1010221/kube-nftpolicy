use anyhow::Context;
use clap::Parser;
use kube_nftpolicy::run::{Options, run};
use kube_nftpolicy::{compile, nft};

/// Enforce Kubernetes NetworkPolicy for this node's pods in an nftables table of the `ip` family.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// This node's name, as Kubernetes knows it: its pods are the ones enforced here.
    #[arg(long, env = "NODE_NAME")]
    node_name: String,
    /// A kubeconfig to reach the API with. Without it, the usual places: KUBECONFIG, ~/.kube/config, or in-cluster.
    #[arg(long)]
    kubeconfig: Option<std::path::PathBuf>,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let config = match &args.kubeconfig {
        Some(path) => {
            let kc = kube::config::Kubeconfig::read_from(path)
                .with_context(|| format!("reading {}", path.display()))?;
            kube::Config::from_custom_kubeconfig(kc, &Default::default()).await?
        }
        None => kube::Config::infer().await?,
    };
    let client = kube::Client::try_from(config)?;
    if args.print {
        let cluster = snapshot(client).await?;
        print!(
            "{}",
            nft::script(&args.table, &compile::compile(&cluster, &args.node_name))
        );
        return Ok(());
    }
    run(
        client,
        Options {
            node: args.node_name,
            table: args.table,
            nft: args.nft,
            once: args.once,
        },
    )
    .await
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
