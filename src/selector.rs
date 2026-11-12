//! Label selectors, with Kubernetes' meaning.

use crate::model::{Labels, Requirement, Selector};

/// Whether `labels` satisfy `selector`. An empty selector selects everything.
pub fn matches(selector: &Selector, labels: &Labels) -> bool {
    selector
        .match_labels
        .iter()
        .all(|(k, v)| labels.get(k) == Some(v))
        && selector.match_expressions.iter().all(|r| holds(r, labels))
}

fn holds(requirement: &Requirement, labels: &Labels) -> bool {
    match requirement {
        Requirement::In(key, values) => labels.get(key).is_some_and(|v| values.contains(v)),
        // NotIn holds for a pod without the key, as it does in Kubernetes.
        Requirement::NotIn(key, values) => labels.get(key).is_none_or(|v| !values.contains(v)),
        Requirement::Exists(key) => labels.contains_key(key),
        Requirement::DoesNotExist(key) => !labels.contains_key(key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn an_empty_selector_selects_everything() {
        assert!(matches(&Selector::default(), &labels(&[])));
        assert!(matches(&Selector::default(), &labels(&[("app", "web")])));
    }

    #[test]
    fn match_labels_needs_every_pair() {
        let s = Selector {
            match_labels: labels(&[("app", "web"), ("tier", "front")]),
            ..Default::default()
        };
        assert!(matches(
            &s,
            &labels(&[("app", "web"), ("tier", "front"), ("x", "y")])
        ));
        assert!(!matches(&s, &labels(&[("app", "web")])));
        assert!(!matches(&s, &labels(&[("app", "web"), ("tier", "back")])));
    }

    #[test]
    fn expressions_have_kubernetes_meaning() {
        let one = |r: Requirement| Selector {
            match_expressions: vec![r],
            ..Default::default()
        };
        let vals = || vec!["a".to_string(), "b".to_string()];
        assert!(matches(
            &one(Requirement::In("k".into(), vals())),
            &labels(&[("k", "a")])
        ));
        assert!(!matches(
            &one(Requirement::In("k".into(), vals())),
            &labels(&[("k", "c")])
        ));
        assert!(!matches(
            &one(Requirement::In("k".into(), vals())),
            &labels(&[])
        ));
        assert!(matches(
            &one(Requirement::NotIn("k".into(), vals())),
            &labels(&[("k", "c")])
        ));
        assert!(matches(
            &one(Requirement::NotIn("k".into(), vals())),
            &labels(&[])
        ));
        assert!(!matches(
            &one(Requirement::NotIn("k".into(), vals())),
            &labels(&[("k", "b")])
        ));
        assert!(matches(
            &one(Requirement::Exists("k".into())),
            &labels(&[("k", "")])
        ));
        assert!(!matches(
            &one(Requirement::Exists("k".into())),
            &labels(&[])
        ));
        assert!(matches(
            &one(Requirement::DoesNotExist("k".into())),
            &labels(&[])
        ));
        assert!(!matches(
            &one(Requirement::DoesNotExist("k".into())),
            &labels(&[("k", "a")])
        ));
    }
}
