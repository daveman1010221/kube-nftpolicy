//! The ruleset's entries as non-overlapping set elements. Entries overlap freely (a policy allowing everything from a
//! block, another one port from a pod inside it), and an nftables interval set of concatenations must not hold
//! overlapping elements, so each local address's entries are cut into disjoint pieces that cover exactly the same
//! traffic.

use crate::compile::{Allow, Ports};
use crate::model::Protocol;
use crate::ranges::Range;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// An element of a set that allows all traffic between `local` and `peer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnyElement {
    pub local: Ipv4Addr,
    pub peer: Range,
}

/// An element of a set that allows `protocol` on ports `start..=end` between `local` and `peer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortElement {
    pub local: Ipv4Addr,
    pub peer: Range,
    pub protocol: Protocol,
    pub start: u16,
    pub end: u16,
}

/// The entries as disjoint elements, in a stable order: those for all traffic, and those for ports.
pub fn disjoint<'a>(
    entries: impl IntoIterator<Item = &'a Allow>,
) -> (Vec<AnyElement>, Vec<PortElement>) {
    let mut any: BTreeMap<Ipv4Addr, Vec<(u64, u64)>> = BTreeMap::new();
    let mut ports: BTreeMap<(Ipv4Addr, Protocol), Vec<Rect>> = BTreeMap::new();
    for a in entries {
        let peer = (u64::from(a.peer.start), u64::from(a.peer.end));
        match a.ports {
            Ports::Any => any.entry(a.local).or_default().push(peer),
            Ports::Range {
                protocol,
                start,
                end,
            } => ports.entry((a.local, protocol)).or_default().push(Rect {
                addr: peer,
                port: (u64::from(start), u64::from(end)),
            }),
        }
    }
    let any_out = any
        .into_iter()
        .flat_map(|(local, ranges)| {
            merge(ranges).into_iter().map(move |(s, e)| AnyElement {
                local,
                peer: range(s, e),
            })
        })
        .collect();
    let mut port_out = Vec::new();
    for ((local, protocol), rects) in ports {
        for (addr, port_ranges) in split(&rects) {
            for (ps, pe) in port_ranges {
                port_out.push(PortElement {
                    local,
                    peer: range(addr.0, addr.1),
                    protocol,
                    start: ps as u16,
                    end: pe as u16,
                });
            }
        }
    }
    (any_out, port_out)
}

#[derive(Debug, Clone, Copy)]
struct Rect {
    addr: (u64, u64),
    port: (u64, u64),
}

/// An address interval and the port intervals allowed across it.
type Band = ((u64, u64), Vec<(u64, u64)>);

fn range(s: u64, e: u64) -> Range {
    Range {
        start: s as u32,
        end: e as u32,
    }
}

/// Overlapping or adjacent inclusive intervals joined, in ascending order.
fn merge(mut v: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    v.sort();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 + 1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// The rectangles as address bands that do not overlap, each with the merged port ranges covering it; neighbouring
/// bands with the same ports are joined.
fn split(rects: &[Rect]) -> Vec<Band> {
    let mut cuts: Vec<u64> = rects
        .iter()
        .flat_map(|r| [r.addr.0, r.addr.1 + 1])
        .collect();
    cuts.sort();
    cuts.dedup();
    let mut bands: Vec<Band> = Vec::new();
    for w in cuts.windows(2) {
        let (s, e) = (w[0], w[1] - 1);
        let ports = merge(
            rects
                .iter()
                .filter(|r| r.addr.0 <= s && s <= r.addr.1)
                .map(|r| r.port)
                .collect(),
        );
        if ports.is_empty() {
            continue;
        }
        match bands.last_mut() {
            Some((addr, p)) if addr.1 + 1 == s && *p == ports => addr.1 = e,
            _ => bands.push(((s, e), ports)),
        }
    }
    bands
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(peer: (u32, u32), ports: Ports) -> Allow {
        Allow {
            local: [10, 0, 0, 1].into(),
            peer: Range {
                start: peer.0,
                end: peer.1,
            },
            ports,
        }
    }

    fn tcp(start: u16, end: u16) -> Ports {
        Ports::Range {
            protocol: Protocol::Tcp,
            start,
            end,
        }
    }

    #[test]
    fn any_ranges_merge() {
        let e = [
            allow((0, 10), Ports::Any),
            allow((5, 20), Ports::Any),
            allow((21, 30), Ports::Any),
            allow((40, 50), Ports::Any),
        ];
        let (any, ports) = disjoint(&e);
        assert!(ports.is_empty());
        assert_eq!(
            any.iter()
                .map(|a| (a.peer.start, a.peer.end))
                .collect::<Vec<_>>(),
            vec![(0, 30), (40, 50)]
        );
    }

    #[test]
    fn a_port_inside_a_wider_grant_is_cut_out_of_overlap() {
        let e = [
            allow((0, 100), tcp(80, 80)),
            allow((50, 50), tcp(0, u16::MAX)),
        ];
        let (_, ports) = disjoint(&e);
        let got: Vec<_> = ports
            .iter()
            .map(|p| (p.peer.start, p.peer.end, p.start, p.end))
            .collect();
        assert_eq!(
            got,
            vec![(0, 49, 80, 80), (50, 50, 0, u16::MAX), (51, 100, 80, 80)]
        );
    }

    #[test]
    fn the_last_address_is_reachable() {
        let e = [allow((0, u32::MAX), tcp(1, 2))];
        let (_, ports) = disjoint(&e);
        assert_eq!(ports.len(), 1);
        assert_eq!((ports[0].peer.start, ports[0].peer.end), (0, u32::MAX));
    }
}
