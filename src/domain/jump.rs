//! Resolution of `proxy_jump` references into an ordered chain of hosts.
//!
//! Both validation and export use [`jump_chain`], so the rules (existing
//! targets, no loops, at most [`MAX_JUMP_HOPS`] hops) cannot drift apart.
//!
//! # ProxyJump limitation (0.1.0)
//!
//! A jump host is written to the exported config as `user@host:port`, taken
//! from the Bifrost store. Its own `IdentityFile` is therefore not used when
//! hopping through it: the jump host's key must be loaded in `ssh-agent` or be
//! one of ssh's default keys.

use std::fmt;

use super::Host;

/// The longest chain of jump hosts Bifrost accepts.
pub const MAX_JUMP_HOPS: usize = 5;

/// Why a jump chain cannot be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A host names itself as its jump host.
    SelfReference,
    /// The jump host does not exist.
    Missing { target: String },
    /// The jump hosts loop back on themselves; `path` lists the hosts involved.
    Cycle { path: Vec<String> },
    /// The chain has more than [`MAX_JUMP_HOPS`] hops.
    TooLong,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::SelfReference => f.write_str("A host cannot be its own jump host."),
            ChainError::Missing { target } => {
                write!(f, "The jump host '{target}' does not exist.")
            }
            ChainError::Cycle { path } => {
                write!(f, "The jump hosts form a loop: {}.", path.join(" -> "))
            }
            ChainError::TooLong => write!(
                f,
                "The chain of jump hosts is too long (at most {MAX_JUMP_HOPS} hops are allowed)."
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// Follows `start.proxy_jump` through `hosts` and returns the jump hosts in
/// connection order: the first element is the first hop ssh connects to
/// (the "outermost" jump host), the last is the one right before `start`.
///
/// Returns an empty chain when `start` has no jump host.
pub fn jump_chain<'a>(hosts: &'a [Host], start: &'a Host) -> Result<Vec<&'a Host>, ChainError> {
    let mut path = vec![start.name.as_str()];
    let mut chain: Vec<&Host> = Vec::new();
    let mut current = start;

    while let Some(target) = &current.proxy_jump {
        if chain.is_empty() && target.eq_ignore_ascii_case(&start.name) {
            return Err(ChainError::SelfReference);
        }
        if path.iter().any(|seen| seen.eq_ignore_ascii_case(target)) {
            let mut looped: Vec<String> = path.iter().map(|name| (*name).to_string()).collect();
            looped.push(target.clone());
            return Err(ChainError::Cycle { path: looped });
        }
        let next = hosts
            .iter()
            .find(|host| host.name.eq_ignore_ascii_case(target))
            .ok_or_else(|| ChainError::Missing {
                target: target.clone(),
            })?;
        if chain.len() == MAX_JUMP_HOPS {
            return Err(ChainError::TooLong);
        }
        chain.push(next);
        path.push(next.name.as_str());
        current = next;
    }

    chain.reverse();
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, jump: Option<&str>) -> Host {
        let mut host = Host::new(name, format!("{name}.example.com"));
        host.proxy_jump = jump.map(str::to_string);
        host
    }

    fn names(chain: Vec<&Host>) -> Vec<&str> {
        chain.into_iter().map(|h| h.name.as_str()).collect()
    }

    #[test]
    fn no_jump_gives_an_empty_chain() {
        let hosts = vec![host("a", None)];
        assert!(jump_chain(&hosts, &hosts[0]).unwrap().is_empty());
    }

    #[test]
    fn chain_is_ordered_from_the_first_hop() {
        // a -> b -> c: ssh connects to c first, then b, then a.
        let hosts = vec![host("a", Some("b")), host("b", Some("c")), host("c", None)];
        assert_eq!(names(jump_chain(&hosts, &hosts[0]).unwrap()), ["c", "b"]);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let hosts = vec![host("a", Some("BASTION")), host("bastion", None)];
        assert_eq!(names(jump_chain(&hosts, &hosts[0]).unwrap()), ["bastion"]);
    }

    #[test]
    fn self_reference_is_rejected() {
        let hosts = vec![host("a", Some("A"))];
        assert_eq!(
            jump_chain(&hosts, &hosts[0]),
            Err(ChainError::SelfReference)
        );
    }

    #[test]
    fn cycles_are_rejected_and_reported() {
        let hosts = vec![
            host("a", Some("b")),
            host("b", Some("c")),
            host("c", Some("a")),
        ];
        let err = jump_chain(&hosts, &hosts[0]).unwrap_err();
        assert_eq!(
            err,
            ChainError::Cycle {
                path: vec!["a".into(), "b".into(), "c".into(), "a".into()]
            }
        );
        assert_eq!(
            err.to_string(),
            "The jump hosts form a loop: a -> b -> c -> a."
        );
    }

    #[test]
    fn a_cycle_that_does_not_include_the_start_is_detected() {
        // a -> b -> c -> b
        let hosts = vec![
            host("a", Some("b")),
            host("b", Some("c")),
            host("c", Some("b")),
        ];
        assert!(matches!(
            jump_chain(&hosts, &hosts[0]),
            Err(ChainError::Cycle { .. })
        ));
    }

    #[test]
    fn missing_targets_are_rejected() {
        let hosts = vec![host("a", Some("ghost"))];
        assert_eq!(
            jump_chain(&hosts, &hosts[0]),
            Err(ChainError::Missing {
                target: "ghost".into()
            })
        );
    }

    fn linear_chain(length: usize) -> Vec<Host> {
        // h0 -> h1 -> ... -> h{length}; h0 has `length` hops.
        (0..=length)
            .map(|i| {
                let next = (i < length).then(|| format!("h{}", i + 1));
                host(&format!("h{i}"), next.as_deref())
            })
            .collect()
    }

    #[test]
    fn five_hops_are_allowed() {
        let hosts = linear_chain(MAX_JUMP_HOPS);
        assert_eq!(jump_chain(&hosts, &hosts[0]).unwrap().len(), 5);
    }

    #[test]
    fn six_hops_are_too_long() {
        let hosts = linear_chain(MAX_JUMP_HOPS + 1);
        assert_eq!(jump_chain(&hosts, &hosts[0]), Err(ChainError::TooLong));
        assert!(ChainError::TooLong.to_string().contains("at most 5 hops"));
    }
}
