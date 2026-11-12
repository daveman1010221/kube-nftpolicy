# kube-nftpolicy

Kubernetes NetworkPolicy, enforced on each node in nftables, IPv4 only.

It is for clusters whose network plugin enforces no NetworkPolicy, where the usual engines cannot run: a kernel built
without IPv6, a rootless cluster, no iptables extensions, no eBPF. It needs only nftables' `ip` table family, and the
one capability to change the node's tables (`NET_ADMIN`).

## Why

The common engines each need something such a node may not have:

- **Calico's nftables dataplane** always creates an IPv6 table (`ip6` family), even with IPv6 support turned off.
- **kube-network-policies** uses the `inet` family, which a kernel without IPv6 does not have.
- **kube-router** uses iptables with ipset extensions.
- **Cilium** loads eBPF programs, which a rootless node cannot.

A kernel without IPv6 is a reasonable thing to run. IPv6 code has been the site of serious kernel vulnerabilities, and
code that is not built cannot be attacked.

## What it enforces

Standard `networking.k8s.io/v1` NetworkPolicy, with its standard meaning:

- ingress and egress, by `policyTypes` or, without them, ingress always and egress when the policy has egress rules;
- peers selected by pod labels, namespace labels, or both, and address blocks with exceptions;
- ports by number, by range (`endPort`) or by a container port's name, for TCP, UDP and SCTP;
- an isolated pod allows the union of what every policy selecting it allows; traffic passes only when the source's
  egress and the destination's ingress both allow it;
- replies to an allowed connection pass; pods on the node's network are neither enforced nor named.

Conversion never widens a policy: a rule whose ports or peers cannot be read at all (an unknown protocol, an IPv6 block)
is dropped, so it allows nothing, rather than read as "every port" or "every peer".

## How it works

Each node runs one instance. It watches pods, namespaces and NetworkPolicies, and for its own pods computes:

- which are isolated for ingress, and which for egress;
- what each may exchange: (pod address, peer address range, protocol, ports).

It writes these into one table, `ip kube_nftpolicy`, as interval sets, and replaces the whole table in one nftables
transaction whenever they change. Its chains hook `forward` (traffic routed through the node, to or from its pods) and
`input` (a pod's traffic to the node itself). Egress is checked where traffic starts and ingress where it ends, so traffic
between two nodes is checked once at each end.

The pipeline is pure until it applies the script: API objects → model → rules → script. `src/spec.rs` states
NetworkPolicy's meaning directly, for one packet; the property tests (`tests/props.rs`) check that the compiled rules
of every node, together, decide every generated packet as it does.

## Running it

**As a node service**, with a kubeconfig whose user the ClusterRole in `deploy/rbac.yaml` binds
(`system:kube-nftpolicy`):

    kube-nftpolicy --node-name "$NODE_NAME" --kubeconfig /etc/kubernetes/kube-nftpolicy.conf

**As a DaemonSet**, on any cluster: build the image (`nix build .#image`), load or push it where your nodes can pull it,
then `kubectl apply -f deploy/`.

`--print` shows the script a node would apply without applying it; `--once` applies it and exits.

## Requirements and limits

- **A routed pod network.** Pod traffic must pass through the node's IP forwarding, as with the `ptp` plugin or
  Calico-style routing. With a bridge plugin, traffic between pods of one node is bridged and never seen, unless the
  node loads `br_netfilter`.
- **IPv4 only.** On a dual-stack cluster, pods' IPv6 traffic is not enforced; it warns at start when pods have IPv6
  addresses.
- **Until it has written its first table, nothing is enforced**, as with other engines. Check enforcement from inside
  the cluster, with a pod that must and must not reach things.
- **A connection already open stays open** when a policy changes to forbid it; new connections follow the new policy.

## Building and testing

    nix build            # the binary, with nft on its PATH; runs the tests
    nix build .#image    # an OCI image for the DaemonSet
    nix develop -c cargo test

`tests/kernel.rs` applies a script in a network namespace of its own (`unshare -rn`), where unprivileged user namespaces
are allowed; it says it skipped where they are not.

## License

Apache-2.0. See `LICENSE`.
