//! The `Host` record and the validated `Hosts` collection.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::Warning;
use super::validate::{self, ValidationError};
use crate::text::escape_control;

/// A port forward. Listeners always bind to localhost, so there is no bind
/// address. For a local forward `listen_port` is on this machine; for a remote
/// forward it is on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub listen_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

/// A saved SSH connection.
///
/// There is deliberately no password field, no `ProxyCommand` and no free-form
/// ssh options: everything Bifrost hands to ssh is one of these validated
/// fields. Unknown keys in the store file are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// Unique (case-insensitive) label shown in Bifrost and used as the
    /// `Host` alias when exporting.
    pub name: String,
    /// IP address or DNS name to connect to.
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// `None` means the ssh default (22).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Path to a private key. Only the path is stored, never key material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    /// Name of another host to hop through.
    ///
    /// # ProxyJump limitation (0.1.0)
    ///
    /// Bifrost expands the jump host to `user@host:port` from its own store,
    /// so the jump host's `identity_file` is not used for the hop. The jump
    /// host's key must be loaded in `ssh-agent` or be one of ssh's default
    /// keys. Chains of up to [`super::jump::MAX_JUMP_HOPS`] hosts are allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_jump: Option<String>,
    /// Off by default; agent forwarding exposes the local agent to the server.
    #[serde(default, skip_serializing_if = "is_false")]
    pub forward_agent: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Private notes. Never exported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_forwards: Vec<Forward>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_forwards: Vec<Forward>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl Host {
    /// A host with only the required fields set.
    pub fn new(name: impl Into<String>, hostname: impl Into<String>) -> Self {
        Host {
            name: name.into(),
            hostname: hostname.into(),
            user: None,
            port: None,
            identity_file: None,
            proxy_jump: None,
            forward_agent: false,
            favorite: false,
            tags: Vec::new(),
            notes: None,
            local_forwards: Vec::new(),
            remote_forwards: Vec::new(),
        }
    }
}

/// Why a change to the collection was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostsError {
    Invalid(ValidationError),
    NotFound(String),
    /// The host cannot be removed because other hosts hop through it.
    InUse {
        name: String,
        dependents: Vec<String>,
    },
}

impl fmt::Display for HostsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostsError::Invalid(err) => err.fmt(f),
            HostsError::NotFound(name) => {
                write!(f, "There is no host named '{}'.", escape_control(name))
            }
            HostsError::InUse { name, dependents } => write!(
                f,
                "Host '{name}' is the jump host of {}. \
                 Change or remove the jump host on those hosts first.",
                dependents
                    .iter()
                    .map(|d| format!("'{d}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl std::error::Error for HostsError {}

impl From<ValidationError> for HostsError {
    fn from(err: ValidationError) -> Self {
        HostsError::Invalid(err)
    }
}

/// A validated collection of hosts, in display order.
///
/// Every mutation validates the collection as a whole and is all-or-nothing:
/// on error the collection is left unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hosts {
    hosts: Vec<Host>,
}

impl Hosts {
    pub fn new() -> Self {
        Hosts::default()
    }

    /// Builds a collection from already-existing data (for example a loaded
    /// file), validating all of it.
    pub fn from_vec(hosts: Vec<Host>) -> Result<Self, ValidationError> {
        validate::check_hosts(&hosts)?;
        Ok(Hosts { hosts })
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Host> {
        self.hosts.iter()
    }

    pub fn as_slice(&self) -> &[Host] {
        &self.hosts
    }

    /// Looks a host up by name, ignoring case.
    pub fn get(&self, name: &str) -> Option<&Host> {
        self.position(name).map(|index| &self.hosts[index])
    }

    fn position(&self, name: &str) -> Option<usize> {
        self.hosts
            .iter()
            .position(|host| host.name.eq_ignore_ascii_case(name))
    }

    /// Names of the hosts that use `name` as their jump host.
    pub fn dependents_of(&self, name: &str) -> Vec<String> {
        self.hosts
            .iter()
            .filter(|host| {
                host.proxy_jump
                    .as_deref()
                    .is_some_and(|jump| jump.eq_ignore_ascii_case(name))
            })
            .map(|host| host.name.clone())
            .collect()
    }

    /// Adds a host.
    ///
    /// Problems that are not errors, such as a missing identity file, are not
    /// reported here; see [`Hosts::warnings`] and
    /// [`validate::identity_file_warning`].
    pub fn add(&mut self, host: Host) -> Result<(), ValidationError> {
        let mut candidate = self.hosts.clone();
        candidate.push(host);
        let last = candidate.len() - 1;
        canonicalize_jump(&mut candidate, last);
        validate::check_hosts(&candidate)?;
        self.hosts = candidate;
        Ok(())
    }

    /// Replaces the host called `current_name` with `host`.
    ///
    /// If the name changes, `proxy_jump` references in other hosts follow it.
    pub fn update(&mut self, current_name: &str, host: Host) -> Result<(), HostsError> {
        let index = self
            .position(current_name)
            .ok_or_else(|| HostsError::NotFound(current_name.to_string()))?;
        let mut candidate = self.hosts.clone();
        let old_name = std::mem::replace(&mut candidate[index], host).name;
        let new_name = candidate[index].name.clone();
        if old_name != new_name {
            for (i, other) in candidate.iter_mut().enumerate() {
                if i != index
                    && other
                        .proxy_jump
                        .as_deref()
                        .is_some_and(|jump| jump.eq_ignore_ascii_case(&old_name))
                {
                    other.proxy_jump = Some(new_name.clone());
                }
            }
        }
        canonicalize_jump(&mut candidate, index);
        validate::check_hosts(&candidate)?;
        self.hosts = candidate;
        Ok(())
    }

    /// Renames a host, updating `proxy_jump` references to it.
    pub fn rename(&mut self, current_name: &str, new_name: &str) -> Result<(), HostsError> {
        let mut host = self
            .get(current_name)
            .cloned()
            .ok_or_else(|| HostsError::NotFound(current_name.to_string()))?;
        host.name = new_name.to_string();
        self.update(current_name, host)
    }

    /// Removes a host, unless other hosts hop through it.
    pub fn remove(&mut self, name: &str) -> Result<Host, HostsError> {
        let index = self
            .position(name)
            .ok_or_else(|| HostsError::NotFound(name.to_string()))?;
        let dependents = self.dependents_of(&self.hosts[index].name);
        if !dependents.is_empty() {
            return Err(HostsError::InUse {
                name: self.hosts[index].name.clone(),
                dependents,
            });
        }
        Ok(self.hosts.remove(index))
    }

    /// Warnings about the whole collection: currently, identity files that do
    /// not exist. This checks the file system, so it is kept apart from
    /// validation. `home` expands a leading `~` in identity file paths; without
    /// it such paths are not checked.
    pub fn warnings(&self, home: Option<&Path>) -> Vec<Warning> {
        self.hosts
            .iter()
            .filter_map(|host| validate::identity_file_warning(host, home))
            .collect()
    }
}

impl<'a> IntoIterator for &'a Hosts {
    type Item = &'a Host;
    type IntoIter = std::slice::Iter<'a, Host>;

    fn into_iter(self) -> Self::IntoIter {
        self.hosts.iter()
    }
}

/// Rewrites `hosts[index].proxy_jump` to the referenced host's exact name.
fn canonicalize_jump(hosts: &mut [Host], index: usize) {
    let canonical = hosts[index].proxy_jump.as_deref().and_then(|target| {
        hosts
            .iter()
            .find(|host| host.name.eq_ignore_ascii_case(target))
            .map(|host| host.name.clone())
    });
    if let Some(name) = canonical {
        hosts[index].proxy_jump = Some(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> Host {
        Host::new(name, format!("{name}.example.com"))
    }

    fn with_jump(name: &str, jump: &str) -> Host {
        let mut h = host(name);
        h.proxy_jump = Some(jump.to_string());
        h
    }

    fn collection(hosts: Vec<Host>) -> Hosts {
        Hosts::from_vec(hosts).expect("fixture should be valid")
    }

    #[test]
    fn add_and_get_are_case_insensitive() {
        let mut hosts = Hosts::new();
        hosts.add(host("Web")).unwrap();
        assert_eq!(hosts.get("WEB").unwrap().name, "Web");
        assert!(hosts.get("db").is_none());
        let err = hosts.add(host("web")).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn invalid_hosts_leave_the_collection_unchanged() {
        let mut hosts = collection(vec![host("a")]);
        let mut bad = host("b");
        bad.hostname = "-oProxyCommand=id".to_string();
        assert!(hosts.add(bad).is_err());
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn add_canonicalizes_the_jump_host_case() {
        let mut hosts = collection(vec![host("Bastion")]);
        hosts.add(with_jump("web", "bastion")).unwrap();
        assert_eq!(
            hosts.get("web").unwrap().proxy_jump.as_deref(),
            Some("Bastion")
        );
    }

    #[test]
    fn add_rejects_missing_and_self_jump_hosts() {
        let mut hosts = Hosts::new();
        assert!(hosts.add(with_jump("a", "ghost")).is_err());
        assert!(hosts.add(with_jump("a", "a")).is_err());
        assert!(hosts.is_empty());
    }

    #[test]
    fn update_can_not_create_a_cycle() {
        let mut hosts = collection(vec![host("a"), with_jump("b", "a")]);
        let err = hosts.update("a", with_jump("a", "b")).unwrap_err();
        assert!(err.to_string().contains("loop"), "{err}");
        assert_eq!(hosts.get("a").unwrap().proxy_jump, None);
    }

    #[test]
    fn update_unknown_host_is_not_found() {
        let mut hosts = Hosts::new();
        assert_eq!(
            hosts.update("ghost", host("x")),
            Err(HostsError::NotFound("ghost".into()))
        );
    }

    #[test]
    fn renaming_a_host_updates_proxy_jump_references() {
        let mut hosts = collection(vec![
            host("bastion"),
            with_jump("web", "bastion"),
            with_jump("db", "BASTION"),
            host("other"),
        ]);
        hosts.rename("bastion", "gateway").unwrap();
        assert!(hosts.get("bastion").is_none());
        assert_eq!(
            hosts.get("web").unwrap().proxy_jump.as_deref(),
            Some("gateway")
        );
        assert_eq!(
            hosts.get("db").unwrap().proxy_jump.as_deref(),
            Some("gateway")
        );
        assert_eq!(hosts.get("other").unwrap().proxy_jump, None);
    }

    #[test]
    fn renaming_by_case_only_keeps_references_valid() {
        let mut hosts = collection(vec![host("bastion"), with_jump("web", "bastion")]);
        hosts.rename("bastion", "Bastion").unwrap();
        assert_eq!(
            hosts.get("web").unwrap().proxy_jump.as_deref(),
            Some("Bastion")
        );
    }

    #[test]
    fn rename_to_an_existing_name_is_rejected() {
        let mut hosts = collection(vec![host("a"), host("b")]);
        assert!(hosts.rename("a", "B").is_err());
        assert!(hosts.get("a").is_some());
    }

    #[test]
    fn update_with_a_new_name_updates_references_too() {
        let mut hosts = collection(vec![host("bastion"), with_jump("web", "bastion")]);
        let mut edited = hosts.get("bastion").unwrap().clone();
        edited.name = "gateway".into();
        edited.hostname = "203.0.113.7".into();
        hosts.update("bastion", edited).unwrap();
        assert_eq!(
            hosts.get("web").unwrap().proxy_jump.as_deref(),
            Some("gateway")
        );
        assert_eq!(hosts.get("gateway").unwrap().hostname, "203.0.113.7");
    }

    #[test]
    fn removing_a_jump_host_in_use_is_refused() {
        let mut hosts = collection(vec![
            host("bastion"),
            with_jump("web", "bastion"),
            with_jump("db", "bastion"),
        ]);
        let err = hosts.remove("bastion").unwrap_err();
        assert_eq!(
            err,
            HostsError::InUse {
                name: "bastion".into(),
                dependents: vec!["web".into(), "db".into()]
            }
        );
        assert_eq!(
            err.to_string(),
            "Host 'bastion' is the jump host of 'web', 'db'. \
             Change or remove the jump host on those hosts first."
        );
        assert_eq!(hosts.len(), 3);
        hosts.remove("web").unwrap();
        hosts.remove("db").unwrap();
        assert_eq!(hosts.remove("bastion").unwrap().name, "bastion");
        assert!(hosts.is_empty());
    }

    #[test]
    fn from_vec_validates_everything() {
        assert!(Hosts::from_vec(vec![host("a"), host("A")]).is_err());
        assert!(Hosts::from_vec(vec![with_jump("a", "b"), with_jump("b", "a")]).is_err());
        assert!(Hosts::from_vec(vec![host("a"), with_jump("b", "a")]).is_ok());
    }

    #[test]
    fn unknown_fields_are_rejected_when_deserializing() {
        let text = "name = \"a\"\nhostname = \"a.example.com\"\nproxy_command = \"nc %h %p\"\n";
        let err = toml::from_str::<Host>(text).unwrap_err();
        assert!(err.to_string().contains("proxy_command"), "{err}");
        let text = "name = \"a\"\nhostname = \"a.example.com\"\npassword = \"hunter2\"\n";
        assert!(toml::from_str::<Host>(text).is_err());
    }
}
