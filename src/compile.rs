//! From the cluster to one node's rules: which of the node's pods are isolated, in which direction, and what each may
//! exchange, as (local address, peer range, ports) entries that `crate::nft` writes into nftables sets.
//!
//! A node enforces only for its own pods: egress where the traffic starts, ingress where it ends. Traffic between two
//! nodes is checked once at each end, and between two pods of one node, both checks happen on that node.
//!
//! A pod starts before the API reports its address, so before the enforcer can know what policy applies to it.
//! Kubernetes requires a pod that an existing policy selects to be isolated before it starts. So, within the node's
//! pod ranges, an address that is no pod the enforcer knows is refused both ways, until the enforcer learns the pod and
//! writes its rules with its address, in one transaction.

use crate::model::{Cluster, Peer, Pod, PortRef, PortSpec, Protocol, Rule};
use crate::ranges::{Range, block_ranges};
use crate::selector::matches;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// Which ports an entry allows: all traffic, or one protocol's port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ports {
    Any,
    Range {
        protocol: Protocol,
        start: u16,
        end: u16,
    },
}

/// One thing a local pod may exchange: with addresses in `peer`, on `ports`. For ingress the peer is the source and
/// the ports the local pod's; for egress the peer is the destination, and the ports its.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Allow {
    pub local: Ipv4Addr,
    pub peer: Range,
    pub ports: Ports,
}

/// One node's rules. Sets, so that the result is the same whatever order the cluster's objects came in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ruleset {
    /// The node's pod address ranges.
    pub pod_ranges: Vec<Range>,
    /// The node's pods' addresses: within `pod_ranges`, the only ones that pass at all.
    pub known: BTreeSet<Ipv4Addr>,
    pub ingress_isolated: BTreeSet<Ipv4Addr>,
    pub egress_isolated: BTreeSet<Ipv4Addr>,
    pub ingress: BTreeSet<Allow>,
    pub egress: BTreeSet<Allow>,
}

/// A packet, as the rules see it. `protocol` is `None` for one that is not TCP, UDP or SCTP (ICMP, say).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: Option<Protocol>,
    pub port: u16,
}

impl Ruleset {
    /// What the node's nftables table decides for a new connection, as `crate::nft` writes it: an address in the
    /// node's pod ranges that is no known pod passes nowhere; an isolated source needs an egress entry, an isolated
    /// destination an ingress entry.
    pub fn allows(&self, p: &Packet) -> bool {
        let unknown =
            |a: Ipv4Addr| self.pod_ranges.iter().any(|r| r.contains(a)) && !self.known.contains(&a);
        if unknown(p.src) || unknown(p.dst) {
            return false;
        }
        let ok = |entries: &BTreeSet<Allow>, local: Ipv4Addr, peer: Ipv4Addr| {
            entries
                .iter()
                .any(|a| a.local == local && a.peer.contains(peer) && ports_admit(a.ports, p))
        };
        (!self.egress_isolated.contains(&p.src) || ok(&self.egress, p.src, p.dst))
            && (!self.ingress_isolated.contains(&p.dst) || ok(&self.ingress, p.dst, p.src))
    }
}

fn ports_admit(ports: Ports, p: &Packet) -> bool {
    match ports {
        Ports::Any => true,
        Ports::Range {
            protocol,
            start,
            end,
        } => p.protocol == Some(protocol) && (start..=end).contains(&p.port),
    }
}

/// The rules for `node`, whose pods get their addresses from `pod_ranges`.
pub fn compile(cluster: &Cluster, node: &str, pod_ranges: &[Range]) -> Ruleset {
    let mut out = Ruleset {
        pod_ranges: pod_ranges.to_vec(),
        ..Default::default()
    };
    // Joined where they overlap or touch: an interval set takes no overlapping elements.
    out.pod_ranges.sort();
    out.pod_ranges.dedup_by(|next, prev| {
        let joins = u64::from(next.start) <= u64::from(prev.end) + 1;
        if joins {
            prev.end = prev.end.max(next.end);
        }
        joins
    });
    let local = cluster
        .pods
        .iter()
        .filter(|p| p.is_addressable() && p.node.as_deref() == Some(node));
    for pod in local {
        let ip = pod.ip.expect("addressable");
        out.known.insert(ip);
        for policy in cluster
            .policies
            .iter()
            .filter(|pol| pol.namespace == pod.namespace && matches(&pol.pod_selector, &pod.labels))
        {
            if let Some(rules) = &policy.ingress {
                out.ingress_isolated.insert(ip);
                for rule in rules {
                    ingress_entries(cluster, &policy.namespace, pod, rule, &mut out.ingress);
                }
            }
            if let Some(rules) = &policy.egress {
                out.egress_isolated.insert(ip);
                for rule in rules {
                    egress_entries(cluster, &policy.namespace, ip, rule, &mut out.egress);
                }
            }
        }
    }
    out
}

/// Ingress to `pod`: from the rule's peers, on its ports, named ports being the pod's own.
fn ingress_entries(
    cluster: &Cluster,
    namespace: &str,
    pod: &Pod,
    rule: &Rule,
    out: &mut BTreeSet<Allow>,
) {
    let local = pod.ip.expect("addressable");
    let ports: Vec<Ports> = port_options(rule)
        .filter_map(|spec| match spec {
            None => Some(Ports::Any),
            Some(spec) => resolve(spec, pod),
        })
        .collect();
    for peer in peer_ranges(cluster, namespace, rule) {
        for &ports in &ports {
            out.insert(Allow { local, peer, ports });
        }
    }
}

/// Egress from `local`: to the rule's peers, on its ports. A named port is resolved against each destination pod, so
/// it reaches only pods that declare it; an address block, which names no pod, gets nothing by name.
fn egress_entries(
    cluster: &Cluster,
    namespace: &str,
    local: Ipv4Addr,
    rule: &Rule,
    out: &mut BTreeSet<Allow>,
) {
    for spec in port_options(rule) {
        match spec {
            Some(
                spec @ PortSpec {
                    port: Some(PortRef::Name(_)),
                    ..
                },
            ) => {
                for dst in peer_pods(cluster, namespace, rule) {
                    if let Some(ports) = resolve(spec, dst) {
                        out.insert(Allow {
                            local,
                            peer: Range::single(dst.ip.expect("addressable")),
                            ports,
                        });
                    }
                }
            }
            _ => {
                let ports = match spec {
                    None => Ports::Any,
                    Some(spec) => match resolve_numeric(spec) {
                        Some(p) => p,
                        None => continue,
                    },
                };
                for peer in peer_ranges(cluster, namespace, rule) {
                    out.insert(Allow { local, peer, ports });
                }
            }
        }
    }
}

/// The rule's port specs, or a single `None` meaning "every port" when it lists none.
fn port_options(rule: &Rule) -> impl Iterator<Item = Option<&PortSpec>> {
    let all = rule.ports.is_empty().then_some(None);
    all.into_iter().chain(rule.ports.iter().map(Some))
}

fn resolve(spec: &PortSpec, pod: &Pod) -> Option<Ports> {
    match &spec.port {
        Some(PortRef::Name(name)) => pod
            .ports
            .iter()
            .find(|p| &p.name == name && p.protocol == spec.protocol)
            .map(|p| Ports::Range {
                protocol: spec.protocol,
                start: p.port,
                end: p.port,
            }),
        _ => resolve_numeric(spec),
    }
}

fn resolve_numeric(spec: &PortSpec) -> Option<Ports> {
    match spec.port {
        None => Some(Ports::Range {
            protocol: spec.protocol,
            start: 0,
            end: u16::MAX,
        }),
        Some(PortRef::Number { port, end }) => {
            let end = end.unwrap_or(port);
            (end >= port).then_some(Ports::Range {
                protocol: spec.protocol,
                start: port,
                end,
            })
        }
        Some(PortRef::Name(_)) => None,
    }
}

/// The address ranges the rule's peers cover: everything when it lists none.
fn peer_ranges(cluster: &Cluster, namespace: &str, rule: &Rule) -> Vec<Range> {
    if rule.peers.is_empty() {
        return vec![Range::ALL];
    }
    let mut out = Vec::new();
    for peer in &rule.peers {
        match peer {
            Peer::Block(block) => out.extend(block_ranges(block)),
            Peer::Pods { .. } => out.extend(
                pods_of(cluster, namespace, peer)
                    .map(|p| Range::single(p.ip.expect("addressable"))),
            ),
        }
    }
    out
}

/// The pods a rule's peers name, for resolving named ports: every addressable pod when it lists no peers.
fn peer_pods<'a>(cluster: &'a Cluster, namespace: &'a str, rule: &'a Rule) -> Vec<&'a Pod> {
    if rule.peers.is_empty() {
        return cluster.pods.iter().filter(|p| p.is_addressable()).collect();
    }
    rule.peers
        .iter()
        .flat_map(|peer| pods_of(cluster, namespace, peer))
        .collect()
}

fn pods_of<'a>(
    cluster: &'a Cluster,
    namespace: &'a str,
    peer: &'a Peer,
) -> impl Iterator<Item = &'a Pod> + 'a {
    cluster
        .pods
        .iter()
        .filter(move |p| p.is_addressable() && peer_names_pod(cluster, namespace, peer, p))
}

/// Whether `peer`, in a policy of `namespace`, names `pod`. Shared with `crate::spec`, which states the meaning
/// directly; selectors are tested on their own.
pub(crate) fn peer_names_pod(cluster: &Cluster, namespace: &str, peer: &Peer, pod: &Pod) -> bool {
    match peer {
        Peer::Block(_) => false,
        Peer::Pods {
            namespaces: None,
            pods,
        } => pod.namespace == namespace && matches(pods, &pod.labels),
        Peer::Pods {
            namespaces: Some(ns),
            pods,
        } => {
            let empty = Default::default();
            let ns_labels = cluster.namespace_labels(&pod.namespace).unwrap_or(&empty);
            matches(ns, ns_labels) && matches(pods, &pod.labels)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cidr, IpBlock, NamedPort, Namespace, Policy, Selector};

    fn pod(ns: &str, name: &str, app: &str, node: &str, ip: [u8; 4]) -> Pod {
        Pod {
            namespace: ns.into(),
            name: name.into(),
            labels: [("app".to_string(), app.to_string())].into(),
            node: Some(node.into()),
            ip: Some(ip.into()),
            host_network: false,
            ports: vec![NamedPort {
                name: "http".into(),
                protocol: Protocol::Tcp,
                port: 8080,
            }],
        }
    }

    fn app(a: &str) -> Selector {
        Selector {
            match_labels: [("app".to_string(), a.to_string())].into(),
            ..Default::default()
        }
    }

    fn cluster(policies: Vec<Policy>) -> Cluster {
        Cluster {
            namespaces: vec![
                Namespace {
                    name: "builds".into(),
                    labels: [(
                        "kubernetes.io/metadata.name".to_string(),
                        "builds".to_string(),
                    )]
                    .into(),
                },
                Namespace {
                    name: "reg".into(),
                    labels: [("kubernetes.io/metadata.name".to_string(), "reg".to_string())].into(),
                },
            ],
            pods: vec![
                pod("builds", "b1", "build", "a", [10, 244, 1, 2]),
                pod("reg", "r1", "registry", "b", [10, 244, 2, 2]),
                pod("reg", "x1", "other", "b", [10, 244, 2, 3]),
            ],
            policies,
        }
    }

    fn pkt(src: [u8; 4], dst: [u8; 4], port: u16) -> Packet {
        Packet {
            src: src.into(),
            dst: dst.into(),
            protocol: Some(Protocol::Tcp),
            port,
        }
    }

    /// The builds' policy: no ingress, egress only to the registry's pods on their named port.
    fn builds_policy() -> Policy {
        Policy {
            namespace: "builds".into(),
            name: "builds".into(),
            pod_selector: Selector::default(),
            ingress: Some(vec![]),
            egress: Some(vec![Rule {
                peers: vec![Peer::Pods {
                    namespaces: Some(Selector {
                        match_labels: [(
                            "kubernetes.io/metadata.name".to_string(),
                            "reg".to_string(),
                        )]
                        .into(),
                        ..Default::default()
                    }),
                    pods: app("registry"),
                }],
                ports: vec![PortSpec {
                    protocol: Protocol::Tcp,
                    port: Some(PortRef::Name("http".into())),
                }],
            }]),
        }
    }

    #[test]
    fn the_builds_policy_reaches_the_registry_and_nothing_else() {
        let c = cluster(vec![builds_policy()]);
        let a = compile(&c, "a", &[]);
        let b = compile(&c, "b", &[]);
        let both = |p: &Packet| a.allows(p) && b.allows(p);
        assert!(both(&pkt([10, 244, 1, 2], [10, 244, 2, 2], 8080)));
        assert!(!both(&pkt([10, 244, 1, 2], [10, 244, 2, 2], 22)));
        assert!(!both(&pkt([10, 244, 1, 2], [10, 244, 2, 3], 8080)));
        assert!(!both(&pkt([10, 244, 1, 2], [1, 1, 1, 1], 443)));
        assert!(
            !both(&pkt([10, 244, 2, 3], [10, 244, 1, 2], 8080)),
            "no ingress"
        );
        assert!(
            both(&pkt([10, 244, 2, 3], [10, 244, 2, 2], 8080)),
            "the registry's namespace is not isolated"
        );
    }

    #[test]
    fn a_node_holds_only_its_own_pods() {
        let c = cluster(vec![builds_policy()]);
        let b = compile(&c, "b", &[]);
        assert!(b.ingress_isolated.is_empty() && b.egress_isolated.is_empty());
        assert!(b.ingress.is_empty() && b.egress.is_empty());
    }

    #[test]
    fn an_ip_block_with_an_exception_lets_the_rest_through() {
        let mut p = builds_policy();
        p.egress = Some(vec![Rule {
            peers: vec![Peer::Block(IpBlock {
                cidr: Cidr {
                    addr: [0, 0, 0, 0].into(),
                    prefix: 0,
                },
                except: vec![Cidr {
                    addr: [10, 0, 0, 0].into(),
                    prefix: 8,
                }],
            })],
            ports: vec![],
        }]);
        let a = compile(&cluster(vec![p]), "a", &[]);
        assert!(a.allows(&pkt([10, 244, 1, 2], [1, 1, 1, 1], 443)));
        assert!(!a.allows(&pkt([10, 244, 1, 2], [10, 244, 2, 2], 8080)));
    }

    #[test]
    fn a_policy_naming_only_ingress_leaves_egress_open() {
        let mut p = builds_policy();
        p.egress = None;
        let a = compile(&cluster(vec![p]), "a", &[]);
        assert!(a.allows(&pkt([10, 244, 1, 2], [1, 1, 1, 1], 443)));
        assert!(!a.allows(&pkt([1, 1, 1, 1], [10, 244, 1, 2], 443)));
    }

    #[test]
    fn a_pod_not_yet_seen_passes_nowhere_until_it_is() {
        let c = cluster(vec![]);
        let range = Range {
            start: u32::from(Ipv4Addr::new(10, 244, 1, 0)),
            end: u32::from(Ipv4Addr::new(10, 244, 1, 255)),
        };
        let a = compile(&c, "a", &[range]);
        assert!(
            a.allows(&pkt([10, 244, 1, 2], [1, 1, 1, 1], 443)),
            "a known pod, no policy"
        );
        assert!(
            !a.allows(&pkt([10, 244, 1, 9], [1, 1, 1, 1], 443)),
            "an address no pod has yet"
        );
        assert!(
            !a.allows(&pkt([10, 244, 2, 2], [10, 244, 1, 9], 8080)),
            "to it either"
        );
        assert!(
            a.allows(&pkt([10, 244, 2, 2], [10, 244, 2, 9], 8080)),
            "another node's range is that node's"
        );
    }

    #[test]
    fn pod_ranges_are_joined_where_they_overlap_or_touch() {
        let r = |s: u32, e: u32| Range { start: s, end: e };
        let a = compile(
            &cluster(vec![]),
            "a",
            &[r(10, 20), r(0, 5), r(21, 30), r(15, 25), r(40, 50)],
        );
        assert_eq!(a.pod_ranges, vec![r(0, 5), r(10, 30), r(40, 50)]);
    }

    #[test]
    fn host_network_pods_are_neither_enforced_nor_peers() {
        let mut c = cluster(vec![builds_policy()]);
        for p in &mut c.pods {
            p.host_network = true;
        }
        assert_eq!(compile(&c, "a", &[]), Ruleset::default());
    }
}
