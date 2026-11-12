//! What the enforcer knows about the cluster, independent of the Kubernetes API's types: the pods, namespaces and
//! policies, reduced to what NetworkPolicy's meaning depends on. `crate::kube` converts the API's objects into these.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub type Labels = BTreeMap<String, String>;

/// A transport protocol a NetworkPolicy port can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

impl Protocol {
    pub const ALL: [Protocol; 3] = [Protocol::Tcp, Protocol::Udp, Protocol::Sctp];

    /// The name nftables uses for it (`inet_proto`).
    pub fn nft_name(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        }
    }
}

/// A port a container declares, which a policy may name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPort {
    pub name: String,
    pub protocol: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pod {
    pub namespace: String,
    pub name: String,
    pub labels: Labels,
    /// The node it is scheduled on, if any.
    pub node: Option<String>,
    /// Its IPv4 address, once it has one. A pod without one is neither enforced nor a peer.
    pub ip: Option<Ipv4Addr>,
    /// On the node's network: NetworkPolicy does not apply to it, and it is no pod peer.
    pub host_network: bool,
    pub ports: Vec<NamedPort>,
}

impl Pod {
    /// Whether policy can apply to it or name it: it has an address of its own.
    pub fn is_addressable(&self) -> bool {
        self.ip.is_some() && !self.host_network
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub name: String,
    pub labels: Labels,
}

/// A label selector: every `match_labels` pair and every expression must hold. An empty selector selects everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selector {
    pub match_labels: Labels,
    pub match_expressions: Vec<Requirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    In(String, Vec<String>),
    NotIn(String, Vec<String>),
    Exists(String),
    DoesNotExist(String),
}

/// An address block and the blocks within it that are excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpBlock {
    pub cidr: Cidr,
    pub except: Vec<Cidr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    /// The first and last address it covers.
    pub fn bounds(self) -> (u32, u32) {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix.min(32)))
        };
        let start = u32::from(self.addr) & mask;
        (start, start | !mask)
    }
}

/// Whom a rule names: pods (by namespace and pod labels) or an address block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peer {
    /// Pods matching `pods` in namespaces matching `namespaces`, or, when `namespaces` is `None`, in the policy's own
    /// namespace.
    Pods {
        namespaces: Option<Selector>,
        pods: Selector,
    },
    Block(IpBlock),
}

/// The port part of a rule. `None` for the port means every port of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub protocol: Protocol,
    pub port: Option<PortRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortRef {
    /// A port, or with `end`, the range from `port` to `end`.
    Number { port: u16, end: Option<u16> },
    /// A container port's name, resolved against the pod the traffic goes to.
    Name(String),
}

/// One ingress or egress rule. Empty `peers` means every peer; empty `ports` means every port and protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rule {
    pub peers: Vec<Peer>,
    pub ports: Vec<PortSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub namespace: String,
    pub name: String,
    pub pod_selector: Selector,
    /// Whether the policy isolates its pods for ingress, and the rules that allow it.
    pub ingress: Option<Vec<Rule>>,
    /// Whether the policy isolates its pods for egress, and the rules that allow it.
    pub egress: Option<Vec<Rule>>,
}

/// Everything the enforcer computes its rules from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cluster {
    pub namespaces: Vec<Namespace>,
    pub pods: Vec<Pod>,
    pub policies: Vec<Policy>,
}

impl Cluster {
    pub fn namespace_labels(&self, name: &str) -> Option<&Labels> {
        self.namespaces
            .iter()
            .find(|n| n.name == name)
            .map(|n| &n.labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cidr_covers_its_block_whatever_its_host_bits() {
        let c = Cidr {
            addr: Ipv4Addr::new(10, 244, 1, 77),
            prefix: 24,
        };
        assert_eq!(
            c.bounds(),
            (
                u32::from(Ipv4Addr::new(10, 244, 1, 0)),
                u32::from(Ipv4Addr::new(10, 244, 1, 255))
            )
        );
        assert_eq!(
            Cidr {
                addr: Ipv4Addr::new(1, 2, 3, 4),
                prefix: 0
            }
            .bounds(),
            (0, u32::MAX)
        );
        let one = Cidr {
            addr: Ipv4Addr::new(1, 2, 3, 4),
            prefix: 32,
        };
        assert_eq!(one.bounds(), (u32::from(one.addr), u32::from(one.addr)));
    }
}
