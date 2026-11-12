//! NetworkPolicy's meaning, stated directly and plainly for one packet, with none of `crate::compile`'s machinery. It
//! is what the compiled rules are checked against (`tests/props.rs`): for any cluster and any packet, the nodes' rules
//! together decide as this does.
//!
//! The rule, from the Kubernetes documentation ("Network Policies"):
//! - a pod is isolated for egress (ingress) when some policy in its namespace selects it and has egress (ingress) in
//!   its policy types; a pod that is not isolated in a direction allows everything in it;
//! - an isolated pod allows what any rule of any policy selecting it allows: the union, so policies only add;
//! - traffic goes through only if the source's egress and the destination's ingress both allow it;
//! - NetworkPolicy does not apply to pods on the node's network, nor name them.

use crate::compile::Packet;
use crate::model::{Cluster, Peer, Pod, PortRef, Rule};
use crate::selector::matches;
use std::net::Ipv4Addr;

/// Whether NetworkPolicy lets `packet` start a connection.
pub fn allows(cluster: &Cluster, packet: &Packet) -> bool {
    let src = pod_at(cluster, packet.src);
    let dst = pod_at(cluster, packet.dst);
    let egress_ok = src.is_none_or(|s| {
        direction_allows(
            cluster,
            s,
            |p| p.egress.as_deref(),
            |rule, ns| {
                peer_admitted(cluster, ns, rule, packet.dst, dst) && ports_admit(rule, dst, packet)
            },
        )
    });
    let ingress_ok = dst.is_none_or(|d| {
        direction_allows(
            cluster,
            d,
            |p| p.ingress.as_deref(),
            |rule, ns| {
                peer_admitted(cluster, ns, rule, packet.src, src)
                    && ports_admit(rule, Some(d), packet)
            },
        )
    });
    egress_ok && ingress_ok
}

fn pod_at(cluster: &Cluster, ip: Ipv4Addr) -> Option<&Pod> {
    cluster
        .pods
        .iter()
        .find(|p| p.ip == Some(ip) && !p.host_network)
}

/// For `pod`, in one direction: allowed when no selecting policy covers the direction, or any of their rules admits.
fn direction_allows<'a>(
    cluster: &'a Cluster,
    pod: &Pod,
    rules_of: impl Fn(&'a crate::model::Policy) -> Option<&'a [Rule]>,
    admits: impl Fn(&Rule, &str) -> bool,
) -> bool {
    let selecting: Vec<_> = cluster
        .policies
        .iter()
        .filter(|p| p.namespace == pod.namespace && matches(&p.pod_selector, &pod.labels))
        .filter_map(|p| rules_of(p).map(|rules| (p, rules)))
        .collect();
    selecting.is_empty()
        || selecting
            .iter()
            .any(|(p, rules)| rules.iter().any(|r| admits(r, &p.namespace)))
}

/// Whether `rule` (of a policy in `namespace`) admits the peer at `peer_ip`, which is `peer_pod` if a pod.
fn peer_admitted(
    cluster: &Cluster,
    namespace: &str,
    rule: &Rule,
    peer_ip: Ipv4Addr,
    peer_pod: Option<&Pod>,
) -> bool {
    rule.peers.is_empty()
        || rule.peers.iter().any(|peer| match peer {
            Peer::Block(b) => {
                let ip = u32::from(peer_ip);
                let within = |c: &crate::model::Cidr| {
                    let (s, e) = c.bounds();
                    (s..=e).contains(&ip)
                };
                within(&b.cidr) && !b.except.iter().any(within)
            }
            Peer::Pods { namespaces, pods } => peer_pod.is_some_and(|p| {
                let ns_ok = match namespaces {
                    None => p.namespace == namespace,
                    Some(sel) => {
                        let labels = cluster
                            .namespace_labels(&p.namespace)
                            .cloned()
                            .unwrap_or_default();
                        matches(sel, &labels)
                    }
                };
                ns_ok && matches(pods, &p.labels)
            }),
        })
}

/// Whether the rule's ports admit the packet, a named port meaning the port the destination pod declares under it.
fn ports_admit(rule: &Rule, dst: Option<&Pod>, packet: &Packet) -> bool {
    rule.ports.is_empty()
        || rule.ports.iter().any(|spec| {
            packet.protocol == Some(spec.protocol)
                && match &spec.port {
                    None => true,
                    Some(PortRef::Number { port, end }) => {
                        (*port..=end.unwrap_or(*port)).contains(&packet.port)
                    }
                    Some(PortRef::Name(name)) => dst.is_some_and(|d| {
                        d.ports.iter().any(|p| {
                            &p.name == name && p.protocol == spec.protocol && p.port == packet.port
                        })
                    }),
                }
        })
}
