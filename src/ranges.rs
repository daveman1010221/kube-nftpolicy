//! Address ranges: an `ipBlock` with its exceptions becomes the disjoint ranges it still covers, since nftables' interval
//! sets hold ranges and have no "except".

use crate::model::IpBlock;
use std::net::Ipv4Addr;

/// An inclusive range of IPv4 addresses, as integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    pub start: u32,
    pub end: u32,
}

impl Range {
    pub const ALL: Range = Range {
        start: 0,
        end: u32::MAX,
    };

    pub fn single(addr: Ipv4Addr) -> Range {
        let a = u32::from(addr);
        Range { start: a, end: a }
    }

    pub fn contains(self, addr: Ipv4Addr) -> bool {
        (self.start..=self.end).contains(&u32::from(addr))
    }
}

/// The block's addresses less every exception, as disjoint ranges in ascending order.
pub fn block_ranges(block: &IpBlock) -> Vec<Range> {
    let (start, end) = block.cidr.bounds();
    let mut holes: Vec<(u32, u32)> = block.except.iter().map(|c| c.bounds()).collect();
    holes.sort();
    let mut out = Vec::new();
    // The next address not yet covered or excluded; u64 so that it may pass u32::MAX.
    let mut next = u64::from(start);
    for (hs, he) in holes {
        let (hs, he) = (u64::from(hs), u64::from(he));
        if he < next || hs > u64::from(end) {
            continue;
        }
        if hs > next {
            out.push(Range {
                start: next as u32,
                end: (hs - 1) as u32,
            });
        }
        next = next.max(he + 1);
    }
    if next <= u64::from(end) {
        out.push(Range {
            start: next as u32,
            end,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Cidr;

    fn cidr(s: &str) -> Cidr {
        let (a, p) = s.split_once('/').unwrap();
        Cidr {
            addr: a.parse().unwrap(),
            prefix: p.parse().unwrap(),
        }
    }

    fn r(a: &str, b: &str) -> Range {
        Range {
            start: u32::from(a.parse::<Ipv4Addr>().unwrap()),
            end: u32::from(b.parse::<Ipv4Addr>().unwrap()),
        }
    }

    #[test]
    fn a_block_without_exceptions_is_one_range() {
        let b = IpBlock {
            cidr: cidr("10.0.0.0/8"),
            except: vec![],
        };
        assert_eq!(block_ranges(&b), vec![r("10.0.0.0", "10.255.255.255")]);
    }

    #[test]
    fn exceptions_cut_holes() {
        let b = IpBlock {
            cidr: cidr("10.0.0.0/24"),
            except: vec![cidr("10.0.0.64/26"), cidr("10.0.0.0/30")],
        };
        assert_eq!(
            block_ranges(&b),
            vec![r("10.0.0.4", "10.0.0.63"), r("10.0.0.128", "10.0.0.255")]
        );
    }

    #[test]
    fn the_whole_space_less_a_block_reaches_the_last_address() {
        let b = IpBlock {
            cidr: cidr("0.0.0.0/0"),
            except: vec![cidr("10.0.0.0/8")],
        };
        assert_eq!(
            block_ranges(&b),
            vec![
                r("0.0.0.0", "9.255.255.255"),
                r("11.0.0.0", "255.255.255.255")
            ]
        );
    }

    #[test]
    fn an_exception_covering_the_block_leaves_nothing() {
        let b = IpBlock {
            cidr: cidr("10.0.0.0/24"),
            except: vec![cidr("10.0.0.0/16")],
        };
        assert!(block_ranges(&b).is_empty());
    }
}
