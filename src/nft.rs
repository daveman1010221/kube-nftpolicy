//! The ruleset as an nftables script, applied in one transaction with `nft -f -`: the table is created if missing,
//! deleted, and written again, so a node never runs half of an old ruleset and half of a new one.
//!
//! Only the `ip` family: the enforcer needs no IPv6 in the kernel, nor the `inet` family.
//!
//! The table's chains:
//! - `forward`, for traffic routed through the node: from a local pod, to a local pod, or both. Replies to an allowed
//!   connection pass first; an address in the node's pod ranges that is no known pod is dropped (a pod the enforcer
//!   has not yet seen); an isolated source then goes through `egress`, an isolated destination through `ingress`.
//! - `input`, for a local pod's traffic to the node's own addresses: the same, egress only, since the node is no pod.
//! - `egress` and `ingress` return when an element allows the packet, and drop it otherwise.
//!
//! Traffic the node itself sends to its pods (the kubelet's probes) goes through neither chain, as NetworkPolicy
//! allows it.

use crate::compile::Ruleset;
use crate::disjoint::{AnyElement, PortElement, disjoint};
use crate::ranges::Range;
use std::fmt::Write;
use std::net::Ipv4Addr;

pub const DEFAULT_TABLE: &str = "kube_nftpolicy";

/// The script that replaces `table` with the ruleset.
pub fn script(table: &str, rules: &Ruleset) -> String {
    let (ingress_any, ingress_ports) = disjoint(&rules.ingress);
    let (egress_any, egress_ports) = disjoint(&rules.egress);
    let mut s = String::new();
    // Created first, so the delete succeeds on the first run too.
    let _ = writeln!(s, "add table ip {table}");
    let _ = writeln!(s, "delete table ip {table}");
    let _ = writeln!(s, "table ip {table} {{");
    let ranges: Vec<String> = rules.pod_ranges.iter().map(|r| range(*r)).collect();
    set(&mut s, "pod_ranges", "ipv4_addr", true, &ranges);
    addr_set(&mut s, "known_pods", rules.known.iter());
    addr_set(&mut s, "ingress_isolated", rules.ingress_isolated.iter());
    addr_set(&mut s, "egress_isolated", rules.egress_isolated.iter());
    any_set(&mut s, "ingress_any", &ingress_any);
    port_set(&mut s, "ingress_ports", &ingress_ports);
    any_set(&mut s, "egress_any", &egress_any);
    port_set(&mut s, "egress_ports", &egress_ports);
    s.push_str(CHAINS);
    s.push_str("}\n");
    s
}

const CHAINS: &str = "\
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tct state established,related accept
\t\tip saddr @pod_ranges ip saddr != @known_pods counter drop
\t\tip daddr @pod_ranges ip daddr != @known_pods counter drop
\t\tip saddr @egress_isolated jump egress
\t\tip daddr @ingress_isolated jump ingress
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tct state established,related accept
\t\tip saddr @pod_ranges ip saddr != @known_pods counter drop
\t\tip saddr @egress_isolated jump egress
\t}
\tchain egress {
\t\tip saddr . ip daddr . meta l4proto . th dport @egress_ports return
\t\tip saddr . ip daddr @egress_any return
\t\tcounter drop
\t}
\tchain ingress {
\t\tip daddr . ip saddr . meta l4proto . th dport @ingress_ports return
\t\tip daddr . ip saddr @ingress_any return
\t\tcounter drop
\t}
";

fn addr_set<'a>(s: &mut String, name: &str, addrs: impl Iterator<Item = &'a Ipv4Addr>) {
    let elements: Vec<String> = addrs.map(|a| a.to_string()).collect();
    set(s, name, "ipv4_addr", false, &elements);
}

fn any_set(s: &mut String, name: &str, elements: &[AnyElement]) {
    let elements: Vec<String> = elements
        .iter()
        .map(|e| format!("{} . {}", e.local, range(e.peer)))
        .collect();
    set(s, name, "ipv4_addr . ipv4_addr", true, &elements);
}

fn port_set(s: &mut String, name: &str, elements: &[PortElement]) {
    let elements: Vec<String> = elements
        .iter()
        .map(|e| {
            let ports = if e.start == e.end {
                e.start.to_string()
            } else {
                format!("{}-{}", e.start, e.end)
            };
            format!(
                "{} . {} . {} . {}",
                e.local,
                range(e.peer),
                e.protocol.nft_name(),
                ports
            )
        })
        .collect();
    set(
        s,
        name,
        "ipv4_addr . ipv4_addr . inet_proto . inet_service",
        true,
        &elements,
    );
}

fn set(s: &mut String, name: &str, ty: &str, interval: bool, elements: &[String]) {
    let _ = writeln!(s, "\tset {name} {{");
    let _ = writeln!(s, "\t\ttype {ty}");
    if interval {
        s.push_str("\t\tflags interval\n");
    }
    // nftables refuses an empty element list, so an empty set has none.
    if !elements.is_empty() {
        let _ = writeln!(
            s,
            "\t\telements = {{\n\t\t\t{}\n\t\t}}",
            elements.join(",\n\t\t\t")
        );
    }
    s.push_str("\t}\n");
}

fn range(r: Range) -> String {
    let (a, b) = (Ipv4Addr::from(r.start), Ipv4Addr::from(r.end));
    if a == b {
        a.to_string()
    } else {
        format!("{a}-{b}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{Allow, Ports};
    use crate::model::Protocol;

    #[test]
    fn an_empty_ruleset_still_makes_the_table_and_its_chains() {
        let s = script(DEFAULT_TABLE, &Ruleset::default());
        assert!(s.starts_with("add table ip kube_nftpolicy\ndelete table ip kube_nftpolicy\n"));
        assert!(!s.contains("elements"));
        assert!(s.contains("chain forward") && s.contains("chain input"));
        assert!(
            !s.contains("inet ") && !s.contains("ip6"),
            "the ip family only"
        );
    }

    #[test]
    fn elements_are_written_as_nft_reads_them() {
        let mut r = Ruleset::default();
        let local: Ipv4Addr = [10, 244, 1, 2].into();
        r.egress_isolated.insert(local);
        r.egress.insert(Allow {
            local,
            peer: Range::single([10, 244, 2, 2].into()),
            ports: Ports::Range {
                protocol: Protocol::Tcp,
                start: 5000,
                end: 5000,
            },
        });
        r.egress.insert(Allow {
            local,
            peer: Range {
                start: u32::from(Ipv4Addr::new(11, 0, 0, 0)),
                end: u32::MAX,
            },
            ports: Ports::Any,
        });
        let s = script("t", &r);
        assert!(s.contains("10.244.1.2 . 10.244.2.2 . tcp . 5000"), "{s}");
        assert!(s.contains("10.244.1.2 . 11.0.0.0-255.255.255.255"), "{s}");
        assert!(s.contains("set egress_isolated {\n\t\ttype ipv4_addr\n\t\telements = {\n\t\t\t10.244.1.2\n\t\t}"), "{s}");
    }
}
