//! The script against a real kernel: applied with `nft -f -` in a network namespace of its own (`unshare -rn`, no
//! privilege needed where unprivileged user namespaces are allowed), twice, as the enforcer rewrites its table. Skipped,
//! with a note, where `unshare` or `nft` cannot run.

use kube_nftpolicy::compile::{Allow, Ports, Ruleset};
use kube_nftpolicy::model::Protocol;
use kube_nftpolicy::nft::{DEFAULT_TABLE, script};
use kube_nftpolicy::ranges::Range;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

fn in_netns(stdin: &str, args: &[&str]) -> Option<(bool, String)> {
    let mut child = Command::new("unshare")
        .args(["-rn", "sh", "-c"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(stdin.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some((out.status.success(), text))
}

fn ruleset() -> Ruleset {
    let local: Ipv4Addr = [10, 244, 1, 2].into();
    let mut r = Ruleset::default();
    r.ingress_isolated.insert(local);
    r.egress_isolated.insert(local);
    for (peer, ports) in [
        (
            Range::single([10, 244, 2, 2].into()),
            Ports::Range {
                protocol: Protocol::Tcp,
                start: 5000,
                end: 5000,
            },
        ),
        (
            Range {
                start: 0,
                end: u32::MAX,
            },
            Ports::Range {
                protocol: Protocol::Udp,
                start: 1000,
                end: 2000,
            },
        ),
        (
            Range {
                start: u32::from(Ipv4Addr::new(11, 0, 0, 0)),
                end: u32::MAX,
            },
            Ports::Any,
        ),
        (
            Range {
                start: 0,
                end: u32::from(Ipv4Addr::new(9, 255, 255, 255)),
            },
            Ports::Any,
        ),
        // Overlaps the first: the disjoint step must cut it.
        (
            Range {
                start: u32::from(Ipv4Addr::new(10, 244, 2, 0)),
                end: u32::from(Ipv4Addr::new(10, 244, 2, 255)),
            },
            Ports::Range {
                protocol: Protocol::Tcp,
                start: 4000,
                end: 6000,
            },
        ),
        (
            Range::single([10, 244, 2, 9].into()),
            Ports::Range {
                protocol: Protocol::Sctp,
                start: 9,
                end: 9,
            },
        ),
    ] {
        r.egress.insert(Allow { local, peer, ports });
        r.ingress.insert(Allow { local, peer, ports });
    }
    r
}

#[test]
fn the_kernel_takes_the_script_and_takes_it_again() {
    let full = script(DEFAULT_TABLE, &ruleset());
    let empty = script(DEFAULT_TABLE, &Ruleset::default());
    let both = format!("{full}{empty}{full}");
    match in_netns(&both, &["nft -f - && nft list table ip kube_nftpolicy"]) {
        None => eprintln!("skipped: unshare could not run"),
        Some((false, text))
            if text.contains("Operation not permitted") || text.contains("not found") =>
        {
            eprintln!("skipped: {text}")
        }
        Some((ok, text)) => {
            assert!(
                ok,
                "nft refused the script:\n{text}\n--- script ---\n{full}"
            );
            // nft lists elements in its own form: ranges as prefixes where they are one, the overlap cut and merged.
            for want in [
                "chain forward",
                "10.244.1.2 . 10.244.2.0/24 . tcp . 4000-6000",
                "10.244.1.2 . 10.244.2.9 . sctp . 9",
                "10.244.1.2 . 11.0.0.0-255.255.255.255",
            ] {
                assert!(text.contains(want), "missing {want:?} in:\n{text}");
            }
        }
    }
}
