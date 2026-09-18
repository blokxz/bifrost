//! Access to the process environment, made injectable for tests.
//!
//! Setting environment variables is `unsafe` in edition 2024 and this crate
//! forbids unsafe code, so everything that reads the environment takes an
//! [`Env`] lookup instead. Production code passes [`process_env`]; tests pass a
//! fake.

use std::ffi::OsString;
use std::path::PathBuf;

/// Looks up an environment variable.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<OsString>;

/// The real process environment.
pub fn process_env(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// Operating system family, as far as path conventions are concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        }
    }
}

/// An environment variable that is set and not empty.
pub fn non_empty(env: Env<'_>, key: &str) -> Option<OsString> {
    env(key).filter(|value| !value.is_empty())
}

/// The user's home directory, if the environment gives an absolute one.
pub fn home_dir(platform: Platform, env: Env<'_>) -> Option<PathBuf> {
    let key = match platform {
        Platform::Windows => "USERPROFILE",
        Platform::Linux | Platform::MacOs => "HOME",
    };
    non_empty(env, key)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::path::PathBuf;

    /// An absolute path that is valid on the platform running the tests.
    pub fn abs(path: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:\\{}", path.replace('/', "\\")))
        } else {
            PathBuf::from(format!("/{path}"))
        }
    }

    /// Builds an env lookup closure from key/value pairs.
    pub fn fake_env(pairs: &[(&str, OsString)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect();
        move |key| map.get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{abs, fake_env};
    use super::*;

    #[test]
    fn home_dir_uses_the_platform_variable() {
        let env = fake_env(&[
            ("HOME", abs("home/rein").into_os_string()),
            ("USERPROFILE", abs("Users/rein").into_os_string()),
        ]);
        assert_eq!(home_dir(Platform::Linux, &env), Some(abs("home/rein")));
        assert_eq!(home_dir(Platform::Windows, &env), Some(abs("Users/rein")));
    }

    #[test]
    fn home_dir_rejects_empty_and_relative_values() {
        let empty = fake_env(&[("HOME", OsString::new())]);
        assert_eq!(home_dir(Platform::Linux, &empty), None);
        let relative = fake_env(&[("HOME", OsString::from("relative/home"))]);
        assert_eq!(home_dir(Platform::Linux, &relative), None);
    }
}
