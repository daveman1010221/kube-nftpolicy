//! The Kubernetes side: the API's NetworkPolicy, Pod and Namespace objects converted into `crate::model`, and the
//! watch that recomputes the node's rules whenever one changes.
//!
//! Conversion never widens what a policy allows. A rule whose every port, or every peer, cannot be read (an unknown
//! protocol, an IPv6 block) is dropped, and allows nothing, rather than read as "every port" or "every peer".

use crate::model::{
    Cidr, Cluster, IpBlock, Labels, NamedPort, Namespace, Peer, Pod, Policy, PortRef, PortSpec,
    Protocol, Requirement, Rule, Selector,
};
use k8s_openapi::api::core::v1::{Namespace as KNamespace, Pod as KPod};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub fn namespace(ns: &KNamespace) -> Option<Namespace> {
    Some(Namespace {
        name: ns.metadata.name.clone()?,
        labels: labels(&ns.metadata.labels),
    })
}

pub fn pod(p: &KPod) -> Option<Pod> {
    let spec = p.spec.as_ref()?;
    let status = p.status.as_ref();
    // A pod that has finished no longer holds its address, which may already be another's.
    let finished = status
        .and_then(|s| s.phase.as_deref())
        .is_some_and(|ph| ph == "Succeeded" || ph == "Failed");
    let ip = if finished {
        None
    } else {
        status.and_then(pod_ipv4)
    };
    let ports = spec
        .containers
        .iter()
        .flat_map(|c| c.ports.iter().flatten())
        .filter_map(|cp| {
            Some(NamedPort {
                name: cp.name.clone()?,
                protocol: protocol(cp.protocol.as_deref())?,
                port: u16::try_from(cp.container_port).ok()?,
            })
        })
        .collect();
    Some(Pod {
        namespace: p.metadata.namespace.clone()?,
        name: p.metadata.name.clone()?,
        labels: labels(&p.metadata.labels),
        node: spec.node_name.clone(),
        ip,
        host_network: spec.host_network.unwrap_or(false),
        ports,
    })
}

fn pod_ipv4(status: &k8s_openapi::api::core::v1::PodStatus) -> Option<Ipv4Addr> {
    let listed = status.pod_ips.iter().flatten().map(|i| i.ip.as_str());
    status
        .pod_ip
        .as_deref()
        .into_iter()
        .chain(listed)
        .find_map(|s| s.parse().ok())
}

pub fn policy(np: &NetworkPolicy) -> Option<Policy> {
    let spec = np.spec.as_ref()?;
    let types = spec.policy_types.as_ref();
    let has = |t: &str| types.is_some_and(|ts| ts.iter().any(|x| x == t));
    // Without policyTypes, a policy isolates for ingress always, and for egress when it has egress rules.
    let isolates_ingress = types.is_none() || has("Ingress");
    let isolates_egress = if types.is_some() {
        has("Egress")
    } else {
        spec.egress.is_some()
    };
    let ingress = isolates_ingress.then(|| {
        spec.ingress
            .iter()
            .flatten()
            .filter_map(|r| rule(r.from.as_deref(), r.ports.as_deref()))
            .collect()
    });
    let egress = isolates_egress.then(|| {
        spec.egress
            .iter()
            .flatten()
            .filter_map(|r| rule(r.to.as_deref(), r.ports.as_deref()))
            .collect()
    });
    Some(Policy {
        namespace: np.metadata.namespace.clone()?,
        name: np.metadata.name.clone()?,
        pod_selector: spec.pod_selector.as_ref().map(selector).unwrap_or_default(),
        ingress,
        egress,
    })
}

/// A rule, or `None` when what it names cannot be read at all, so that it allows nothing.
fn rule(peers: Option<&[NetworkPolicyPeer]>, ports: Option<&[NetworkPolicyPort]>) -> Option<Rule> {
    let given_peers = peers.unwrap_or_default();
    let given_ports = ports.unwrap_or_default();
    let peers: Vec<Peer> = given_peers.iter().filter_map(peer).collect();
    let ports: Vec<PortSpec> = given_ports.iter().filter_map(port).collect();
    if (!given_peers.is_empty() && peers.is_empty())
        || (!given_ports.is_empty() && ports.is_empty())
    {
        return None;
    }
    Some(Rule { peers, ports })
}

fn peer(p: &NetworkPolicyPeer) -> Option<Peer> {
    if let Some(block) = &p.ip_block {
        return Some(Peer::Block(IpBlock {
            cidr: cidr(&block.cidr)?,
            // An exception that cannot be read cannot be honoured, so the block is not used at all.
            except: block
                .except
                .iter()
                .flatten()
                .map(|c| cidr(c))
                .collect::<Option<Vec<_>>>()?,
        }));
    }
    match (&p.namespace_selector, &p.pod_selector) {
        (None, None) => None,
        (ns, pods) => Some(Peer::Pods {
            namespaces: ns.as_ref().map(selector),
            pods: pods.as_ref().map(selector).unwrap_or_default(),
        }),
    }
}

fn port(p: &NetworkPolicyPort) -> Option<PortSpec> {
    let protocol = protocol(p.protocol.as_deref())?;
    let port = match &p.port {
        None => None,
        Some(IntOrString::Int(n)) => Some(PortRef::Number {
            port: u16::try_from(*n).ok()?,
            end: match p.end_port {
                None => None,
                Some(e) => Some(u16::try_from(e).ok()?),
            },
        }),
        Some(IntOrString::String(name)) => Some(PortRef::Name(name.clone())),
    };
    Some(PortSpec { protocol, port })
}

fn protocol(p: Option<&str>) -> Option<Protocol> {
    match p.unwrap_or("TCP") {
        "TCP" => Some(Protocol::Tcp),
        "UDP" => Some(Protocol::Udp),
        "SCTP" => Some(Protocol::Sctp),
        _ => None,
    }
}

/// An IPv4 CIDR, or `None` for anything else.
pub fn cidr(s: &str) -> Option<Cidr> {
    let (addr, prefix) = s.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= 32).then_some(Cidr {
        addr: addr.parse().ok()?,
        prefix,
    })
}

fn labels(l: &Option<BTreeMap<String, String>>) -> Labels {
    l.clone().unwrap_or_default()
}

fn selector(s: &LabelSelector) -> Selector {
    Selector {
        match_labels: s.match_labels.clone().unwrap_or_default(),
        match_expressions: s
            .match_expressions
            .iter()
            .flatten()
            .map(|e| {
                let values = e.values.clone().unwrap_or_default();
                match e.operator.as_str() {
                    "In" => Requirement::In(e.key.clone(), values),
                    "NotIn" => Requirement::NotIn(e.key.clone(), values),
                    "Exists" => Requirement::Exists(e.key.clone()),
                    "DoesNotExist" => Requirement::DoesNotExist(e.key.clone()),
                    // An operator this code does not know selects nothing.
                    _ => Requirement::In(e.key.clone(), vec![]),
                }
            })
            .collect(),
    }
}

/// The cluster, from the watched objects.
pub fn cluster<'a>(
    namespaces: impl IntoIterator<Item = &'a KNamespace>,
    pods: impl IntoIterator<Item = &'a KPod>,
    policies: impl IntoIterator<Item = &'a NetworkPolicy>,
) -> Cluster {
    Cluster {
        namespaces: namespaces.into_iter().filter_map(namespace).collect(),
        pods: pods.into_iter().filter_map(pod).collect(),
        policies: policies.into_iter().filter_map(policy).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::{IPBlock, NetworkPolicyEgressRule, NetworkPolicySpec};
    use kube::api::ObjectMeta;

    fn np(spec: NetworkPolicySpec) -> NetworkPolicy {
        NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("p".into()),
                namespace: Some("ns".into()),
                ..Default::default()
            },
            spec: Some(spec),
        }
    }

    #[test]
    fn without_policy_types_egress_isolates_only_with_egress_rules() {
        let p = policy(&np(NetworkPolicySpec::default())).unwrap();
        assert_eq!(p.ingress, Some(vec![]));
        assert_eq!(p.egress, None);
        let p = policy(&np(NetworkPolicySpec {
            egress: Some(vec![]),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(p.egress, Some(vec![]));
    }

    #[test]
    fn policy_types_decide_isolation() {
        let p = policy(&np(NetworkPolicySpec {
            policy_types: Some(vec!["Egress".into()]),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(p.ingress, None);
        assert_eq!(p.egress, Some(vec![]));
    }

    #[test]
    fn a_rule_whose_ports_cannot_be_read_allows_nothing_rather_than_everything() {
        let spec = NetworkPolicySpec {
            policy_types: Some(vec!["Egress".into()]),
            egress: Some(vec![NetworkPolicyEgressRule {
                ports: Some(vec![NetworkPolicyPort {
                    protocol: Some("ICMP".into()),
                    ..Default::default()
                }]),
                to: None,
            }]),
            ..Default::default()
        };
        assert_eq!(policy(&np(spec)).unwrap().egress, Some(vec![]));
    }

    #[test]
    fn an_ipv6_block_is_no_peer_and_does_not_widen_the_rule() {
        let spec = NetworkPolicySpec {
            policy_types: Some(vec!["Egress".into()]),
            egress: Some(vec![NetworkPolicyEgressRule {
                to: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "fd00::/8".into(),
                        except: None,
                    }),
                    ..Default::default()
                }]),
                ports: None,
            }]),
            ..Default::default()
        };
        assert_eq!(policy(&np(spec)).unwrap().egress, Some(vec![]));
    }
}
