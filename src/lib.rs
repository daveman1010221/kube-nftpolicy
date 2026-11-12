//! kube-nftpolicy: Kubernetes NetworkPolicy, enforced on each node in nftables, IPv4 only.
//!
//! The pipeline is pure until its last step: the API's objects become a [`model::Cluster`] (`kube`), the cluster
//! becomes one node's [`compile::Ruleset`] (`compile`), and the ruleset becomes an nftables script (`nft`), which
//! `run` applies. `spec` states NetworkPolicy's meaning directly, and the property tests hold the compiled rules to
//! it.

pub mod compile;
pub mod disjoint;
pub mod kube;
pub mod model;
pub mod nft;
pub mod ranges;
pub mod run;
pub mod selector;
pub mod spec;
