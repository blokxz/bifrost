//! The on-disk schema of `hosts.toml`.
//!
//! ```toml
//! version = 1
//!
//! [[hosts]]
//! name = "web"
//! hostname = "web.example.com"
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::StoreError;
use crate::domain::{Host, Hosts};

/// The file format version this build reads and writes.
pub const CURRENT_VERSION: u32 = 1;

/// Only the version, read first so that files from a newer Bifrost are
/// recognized before their (possibly different) schema is interpreted.
#[derive(Deserialize)]
struct VersionProbe {
    version: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIn {
    #[allow(dead_code)]
    version: u32,
    #[serde(default)]
    hosts: Vec<Host>,
}

#[derive(Serialize)]
struct FileOut<'a> {
    version: u32,
    hosts: &'a [Host],
}

/// Parses and fully validates the contents of a store file.
pub(crate) fn parse(text: &str, path: &Path, backup: &Path) -> Result<Hosts, StoreError> {
    let parse_error = |err: toml::de::Error| StoreError::Parse {
        path: path.to_path_buf(),
        backup: backup.to_path_buf(),
        message: err.to_string(),
    };

    let probe: VersionProbe = toml::from_str(text).map_err(parse_error)?;
    match probe.version {
        None => {
            return Err(StoreError::MissingVersion {
                path: path.to_path_buf(),
                backup: backup.to_path_buf(),
            });
        }
        Some(found) if found > i64::from(CURRENT_VERSION) => {
            return Err(StoreError::NewerVersion {
                path: path.to_path_buf(),
                found,
                supported: CURRENT_VERSION,
            });
        }
        Some(found) if found < 1 => {
            return Err(StoreError::BadVersion {
                path: path.to_path_buf(),
                backup: backup.to_path_buf(),
                found,
            });
        }
        Some(_) => {}
    }

    let file: FileIn = toml::from_str(text).map_err(parse_error)?;
    Hosts::from_vec(file.hosts).map_err(|error| {
        let line = error.host_index().and_then(|index| host_line(text, index));
        StoreError::Invalid {
            path: path.to_path_buf(),
            backup: backup.to_path_buf(),
            error: Box::new(error),
            line,
        }
    })
}

/// Serializes the collection with `version = 1` first.
pub(crate) fn serialize(hosts: &Hosts) -> Result<String, StoreError> {
    let file = FileOut {
        version: CURRENT_VERSION,
        hosts: hosts.as_slice(),
    };
    toml::to_string(&file).map_err(|err| StoreError::Serialize(err.to_string()))
}

/// The 1-based line of the `[[hosts]]` header of the host at `index`.
fn host_line(text: &str, index: usize) -> Option<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| line.trim_start().starts_with("[[hosts]]"))
        .nth(index)
        .map(|(number, _)| number + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(text: &str) -> Result<Hosts, StoreError> {
        parse(
            text,
            Path::new("/x/hosts.toml"),
            Path::new("/x/hosts.toml.bak"),
        )
    }

    #[test]
    fn version_comes_first_in_the_output() {
        let mut hosts = Hosts::new();
        hosts.add(Host::new("web", "web.example.com")).unwrap();
        let text = serialize(&hosts).unwrap();
        assert!(text.starts_with("version = 1\n"), "{text}");
        assert!(text.contains("[[hosts]]"));
    }

    #[test]
    fn empty_collection_roundtrips() {
        let text = serialize(&Hosts::new()).unwrap();
        assert_eq!(parse_str(&text).unwrap(), Hosts::new());
    }

    #[test]
    fn file_without_hosts_is_an_empty_store() {
        assert!(parse_str("version = 1\n").unwrap().is_empty());
    }

    #[test]
    fn missing_version_is_reported() {
        assert!(matches!(
            parse_str("[[hosts]]\nname = \"a\"\nhostname = \"a.example.com\"\n"),
            Err(StoreError::MissingVersion { .. })
        ));
    }

    #[test]
    fn version_zero_is_reported() {
        assert!(matches!(
            parse_str("version = 0\n"),
            Err(StoreError::BadVersion { found: 0, .. })
        ));
    }

    #[test]
    fn newer_versions_are_detected_before_the_schema_is_read() {
        // A future schema may use fields this build does not know.
        let text = "version = 2\n[[hosts]]\nnew_thing = true\n";
        match parse_str(text) {
            Err(StoreError::NewerVersion {
                found, supported, ..
            }) => {
                assert_eq!((found, supported), (2, 1));
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn syntax_errors_include_the_location() {
        let err = parse_str("version = 1\n[[hosts]\nname = \"a\"\n").unwrap_err();
        assert!(matches!(err, StoreError::Parse { .. }));
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = "version = 1\n[[hosts]]\nname = \"a\"\nhostname = \"a.example.com\"\n\
                    proxy_command = \"nc %h %p\"\n";
        let err = parse_str(text).unwrap_err();
        assert!(matches!(err, StoreError::Parse { .. }));
        assert!(err.to_string().contains("proxy_command"), "{err}");
        assert!(parse_str("version = 1\nsurprise = 1\n").is_err());
    }

    #[test]
    fn invalid_hosts_report_the_line_of_their_table() {
        let text = "version = 1\n\
                    \n\
                    [[hosts]]\n\
                    name = \"good\"\n\
                    hostname = \"good.example.com\"\n\
                    \n\
                    [[hosts]]\n\
                    name = \"bad\"\n\
                    hostname = \"bad.example.com\"\n\
                    port = 0\n";
        match parse_str(text).unwrap_err() {
            StoreError::Invalid { error, line, .. } => {
                assert_eq!(error.host_name(), Some("bad"));
                assert_eq!(line, Some(7));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn out_of_range_ports_are_parse_errors() {
        let text =
            "version = 1\n[[hosts]]\nname = \"a\"\nhostname = \"a.example.com\"\nport = 70000\n";
        assert!(matches!(parse_str(text), Err(StoreError::Parse { .. })));
    }

    #[test]
    fn all_fields_roundtrip() {
        let mut jump = Host::new("bastion", "203.0.113.1");
        jump.user = Some("admin".into());
        let mut host = Host::new("web", "web.example.com");
        host.user = Some("deploy".into());
        host.port = Some(2222);
        host.identity_file = Some("~/.ssh/id_ed25519".into());
        host.proxy_jump = Some("bastion".into());
        host.forward_agent = true;
        host.favorite = true;
        host.tags = vec!["prod".into(), "eu-west".into()];
        host.notes = Some("first line\nsecond \"quoted\" line".into());
        host.local_forwards = vec![crate::domain::Forward {
            listen_port: 5433,
            dest_host: "db.internal".into(),
            dest_port: 5432,
        }];
        host.remote_forwards = vec![crate::domain::Forward {
            listen_port: 9000,
            dest_host: "localhost".into(),
            dest_port: 3000,
        }];
        let hosts = Hosts::from_vec(vec![jump, host]).unwrap();

        let text = serialize(&hosts).unwrap();
        assert_eq!(parse_str(&text).unwrap(), hosts);
    }
}
