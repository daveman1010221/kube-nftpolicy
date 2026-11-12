//! Properties of the pipeline, over small generated clusters:
//! - the nodes' compiled rules, together, decide every packet as NetworkPolicy's meaning (`spec`) does;
//! - a node's rules do not depend on the order the cluster's objects came in;
//! - an ipBlock's ranges hold exactly the block's addresses less its exceptions;
//! - the disjoint set elements cover exactly what the entries cover, and do not overlap.

use kube_nftpolicy::compile::{Allow, Packet, Ports, compile};
use kube_nftpolicy::disjoint::disjoint;
use kube_nftpolicy::model::*;
use kube_nftpolicy::ranges::{Range, block_ranges};
use kube_nftpolicy::spec;
use proptest::prelude::*;
use std::net::Ipv4Addr;

const NODES: [&str; 2] = ["node-a", "node-b"];
const NAMESPACES: [&str; 3] = ["n0", "n1", "n2"];
const PORTS: [u16; 4] = [22, 80, 81, 443];

fn kv(k: &str, v: &str) -> (String, String) {
    (k.to_string(), v.to_string())
}

fn labels() -> impl Strategy<Value = Labels> {
    (
        prop::option::of(prop::sample::select(vec!["a", "b"])),
        prop::option::of(prop::sample::select(vec!["x", "y"])),
    )
        .prop_map(|(app, tier)| {
            let mut l = Labels::new();
            if let Some(a) = app {
                l.insert("app".into(), a.into());
            }
            if let Some(t) = tier {
                l.insert("tier".into(), t.into());
            }
            l
        })
}

fn selector() -> impl Strategy<Value = Selector> {
    let req = prop_oneof![
        prop::sample::select(vec!["a", "b"])
            .prop_map(|v| Requirement::In("app".into(), vec![v.into()])),
        prop::sample::select(vec!["a", "b"])
            .prop_map(|v| Requirement::NotIn("app".into(), vec![v.into()])),
        Just(Requirement::Exists("tier".into())),
        Just(Requirement::DoesNotExist("tier".into())),
    ];
    (labels(), prop::collection::vec(req, 0..2)).prop_map(|(match_labels, match_expressions)| {
        Selector {
            match_labels,
            match_expressions,
        }
    })
}

fn ns_selector() -> impl Strategy<Value = Selector> {
    prop_oneof![
        Just(Selector::default()),
        prop::sample::select(NAMESPACES.to_vec()).prop_map(|n| Selector {
            match_labels: [kv("kubernetes.io/metadata.name", n)].into(),
            ..Default::default()
        }),
        prop::sample::select(vec!["x", "y"]).prop_map(|t| Selector {
            match_labels: [kv("team", t)].into(),
            ..Default::default()
        }),
    ]
}

fn cidr() -> impl Strategy<Value = Cidr> {
    prop_oneof![
        (0u8..8, prop::sample::select(vec![29u8, 30, 31, 32])).prop_map(|(host, prefix)| Cidr {
            addr: Ipv4Addr::new(10, 0, 0, host * 2),
            prefix
        }),
        Just(Cidr {
            addr: Ipv4Addr::new(0, 0, 0, 0),
            prefix: 0
        }),
        Just(Cidr {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 24
        }),
        Just(Cidr {
            addr: Ipv4Addr::new(1, 1, 1, 0),
            prefix: 24
        }),
    ]
}

fn peer() -> impl Strategy<Value = Peer> {
    prop_oneof![
        (prop::option::of(ns_selector()), selector())
            .prop_map(|(namespaces, pods)| Peer::Pods { namespaces, pods }),
        (cidr(), prop::collection::vec(cidr(), 0..2))
            .prop_map(|(cidr, except)| Peer::Block(IpBlock { cidr, except })),
    ]
}

fn protocol() -> impl Strategy<Value = Protocol> {
    prop::sample::select(vec![Protocol::Tcp, Protocol::Udp])
}

fn port_spec() -> impl Strategy<Value = PortSpec> {
    let port = prop_oneof![
        Just(None),
        (
            prop::sample::select(PORTS.to_vec()),
            prop::option::of(prop::sample::select(vec![81u16, 443]))
        )
            .prop_map(|(port, end)| Some(PortRef::Number { port, end })),
        prop::sample::select(vec!["p1", "p2"]).prop_map(|n| Some(PortRef::Name(n.into()))),
    ];
    (protocol(), port).prop_map(|(protocol, port)| PortSpec { protocol, port })
}

fn rule() -> impl Strategy<Value = Rule> {
    (
        prop::collection::vec(peer(), 0..3),
        prop::collection::vec(port_spec(), 0..3),
    )
        .prop_map(|(peers, ports)| Rule { peers, ports })
}

fn rules() -> impl Strategy<Value = Option<Vec<Rule>>> {
    prop::option::of(prop::collection::vec(rule(), 0..3))
}

fn policy() -> impl Strategy<Value = Policy> {
    (
        prop::sample::select(NAMESPACES.to_vec()),
        selector(),
        rules(),
        rules(),
    )
        .prop_map(|(ns, pod_selector, ingress, egress)| Policy {
            namespace: ns.into(),
            name: "p".into(),
            pod_selector,
            ingress,
            egress,
        })
}

fn named_port() -> impl Strategy<Value = NamedPort> {
    (
        prop::sample::select(vec!["p1", "p2"]),
        protocol(),
        prop::sample::select(PORTS.to_vec()),
    )
        .prop_map(|(name, protocol, port)| NamedPort {
            name: name.into(),
            protocol,
            port,
        })
}

/// A pod at 10.0.0.(i + 1), so addresses are unique and some fall inside the generated blocks.
fn pod(i: u8) -> impl Strategy<Value = Pod> {
    (
        prop::sample::select(NAMESPACES.to_vec()),
        labels(),
        prop::sample::select(NODES.to_vec()),
        prop::bool::weighted(0.1),
        prop::collection::vec(named_port(), 0..3),
    )
        .prop_map(move |(ns, labels, node, host_network, ports)| Pod {
            namespace: ns.into(),
            name: format!("pod{i}"),
            labels,
            node: Some(node.into()),
            ip: Some(Ipv4Addr::new(10, 0, 0, i + 1)),
            host_network,
            ports,
        })
}

fn cluster() -> impl Strategy<Value = Cluster> {
    let pods = (0u8..7).prop_flat_map(|n| (0..n).map(pod).collect::<Vec<_>>());
    let teams = prop::collection::vec(prop::sample::select(vec!["x", "y"]), 3);
    (pods, prop::collection::vec(policy(), 0..4), teams).prop_map(|(pods, policies, teams)| {
        Cluster {
            namespaces: NAMESPACES
                .iter()
                .zip(teams)
                .map(|(n, t)| Namespace {
                    name: n.to_string(),
                    labels: [kv("kubernetes.io/metadata.name", n), kv("team", t)].into(),
                })
                .collect(),
            pods,
            policies,
        }
    })
}

fn address() -> impl Strategy<Value = Ipv4Addr> {
    prop_oneof![
        (1u8..8).prop_map(|i| Ipv4Addr::new(10, 0, 0, i)),
        Just(Ipv4Addr::new(10, 0, 0, 200)),
        Just(Ipv4Addr::new(1, 1, 1, 1)),
    ]
}

fn packet() -> impl Strategy<Value = Packet> {
    (
        address(),
        address(),
        prop::option::of(protocol()),
        prop::sample::select(PORTS.to_vec()),
    )
        .prop_map(|(src, dst, protocol, port)| Packet {
            src,
            dst,
            protocol,
            port,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn the_nodes_rules_decide_as_networkpolicy_means(c in cluster(), packets in prop::collection::vec(packet(), 1..20)) {
        let rules: Vec<_> = NODES.iter().map(|n| compile(&c, n)).collect();
        for p in &packets {
            let by_rules = rules.iter().all(|r| r.allows(p));
            prop_assert_eq!(by_rules, spec::allows(&c, p), "packet {:?}", p);
        }
    }

    #[test]
    fn a_nodes_rules_do_not_depend_on_the_order_of_the_objects(c in cluster(), seed in any::<u64>()) {
        let mut shuffled = c.clone();
        let mut rng = seed;
        let mut shuffle = |n: usize| -> Vec<usize> {
            let mut idx: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                idx.swap(i, (rng >> 33) as usize % (i + 1));
            }
            idx
        };
        shuffled.pods = shuffle(c.pods.len()).into_iter().map(|i| c.pods[i].clone()).collect();
        shuffled.policies = shuffle(c.policies.len()).into_iter().map(|i| c.policies[i].clone()).collect();
        shuffled.namespaces = shuffle(c.namespaces.len()).into_iter().map(|i| c.namespaces[i].clone()).collect();
        for n in NODES {
            prop_assert_eq!(compile(&c, n), compile(&shuffled, n));
        }
    }

    #[test]
    fn a_blocks_ranges_are_its_addresses_less_its_exceptions(cidr in cidr(), except in prop::collection::vec(cidr(), 0..3), probes in prop::collection::vec(any::<u32>().prop_map(|a| (a % 512) | 0x0a00_0000), 1..40)) {
        let block = IpBlock { cidr, except };
        let ranges = block_ranges(&block);
        for w in ranges.windows(2) {
            prop_assert!(w[0].end < w[1].start, "ascending and disjoint: {:?}", ranges);
        }
        let within = |c: &Cidr, a: u32| { let (s, e) = c.bounds(); (s..=e).contains(&a) };
        for a in probes.into_iter().chain([0, u32::MAX, u32::from(Ipv4Addr::new(1, 1, 1, 1))]) {
            let expected = within(&block.cidr, a) && !block.except.iter().any(|x| within(x, a));
            prop_assert_eq!(ranges.iter().any(|r| r.contains(Ipv4Addr::from(a))), expected, "address {}", Ipv4Addr::from(a));
        }
    }

    #[test]
    fn disjoint_elements_cover_the_entries_exactly_and_never_overlap(
        entries in prop::collection::vec(
            ((0u32..40), (0u32..40), prop_oneof![Just(None), (protocol(), 0u16..20, 0u16..20).prop_map(Some)]),
            0..12,
        ),
        probes in prop::collection::vec((0u32..45, prop::option::of(protocol()), 0u16..25), 1..60),
    ) {
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let allows: Vec<Allow> = entries.iter().map(|&(a, b, ports)| Allow {
            local,
            peer: Range { start: a.min(b), end: a.max(b) },
            ports: match ports {
                None => Ports::Any,
                Some((protocol, s, e)) => Ports::Range { protocol, start: s.min(e), end: s.max(e) },
            },
        }).collect();
        let (any, ports) = disjoint(&allows);
        for (i, x) in any.iter().enumerate() {
            for y in &any[i + 1..] {
                prop_assert!(x.local != y.local || x.peer.end < y.peer.start || y.peer.end < x.peer.start);
            }
        }
        for (i, x) in ports.iter().enumerate() {
            for y in &ports[i + 1..] {
                let addr_apart = x.peer.end < y.peer.start || y.peer.end < x.peer.start;
                let port_apart = x.end < y.start || y.end < x.start;
                prop_assert!(x.local != y.local || x.protocol != y.protocol || addr_apart || port_apart, "{:?} {:?}", x, y);
            }
        }
        for (addr, protocol, port) in probes {
            let ip = Ipv4Addr::from(addr);
            let p = Packet { src: local, dst: ip, protocol, port };
            let by_entries = allows.iter().any(|a| a.peer.contains(ip) && match a.ports {
                Ports::Any => true,
                Ports::Range { protocol: pr, start, end } => p.protocol == Some(pr) && (start..=end).contains(&port),
            });
            let by_elements = any.iter().any(|e| e.peer.contains(ip))
                || ports.iter().any(|e| e.peer.contains(ip) && Some(e.protocol) == protocol && (e.start..=e.end).contains(&port));
            prop_assert_eq!(by_entries, by_elements, "probe {} {:?} {}", ip, protocol, port);
        }
    }
}
