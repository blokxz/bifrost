//! Where the Bifrost config directory lives.

use std::path::PathBuf;

use super::StoreError;
use crate::sysenv::{self, Env, Platform};

/// Environment variable that overrides the config directory. Must be absolute.
pub const CONFIG_DIR_VAR: &str = "BIFROST_CONFIG_DIR";

/// The config directory for the running platform, honoring `BIFROST_CONFIG_DIR`.
pub fn config_dir(env: Env<'_>) -> Result<PathBuf, StoreError> {
    config_dir_for(Platform::current(), env)
}

/// Same as [`config_dir`] for an explicit platform (used by tests):
///
/// - `BIFROST_CONFIG_DIR`, if set (must be absolute), on every platform
/// - Linux: `$XDG_CONFIG_HOME/bifrost`, default `~/.config/bifrost`
/// - macOS: `~/Library/Application Support/bifrost`
/// - Windows: `%APPDATA%\bifrost`
pub fn config_dir_for(platform: Platform, env: Env<'_>) -> Result<PathBuf, StoreError> {
    if let Some(value) = sysenv::non_empty(env, CONFIG_DIR_VAR) {
        let dir = PathBuf::from(value);
        if !dir.is_absolute() {
            return Err(StoreError::RelativeConfigDir(dir));
        }
        return Ok(dir);
    }

    let no_home = || {
        StoreError::NoConfigDir(match platform {
            Platform::Windows => "USERPROFILE is not set to an absolute path".to_string(),
            _ => "HOME is not set to an absolute path".to_string(),
        })
    };

    match platform {
        Platform::Windows => sysenv::non_empty(env, "APPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|appdata| appdata.join("bifrost"))
            .ok_or_else(|| {
                StoreError::NoConfigDir("APPDATA is not set to an absolute path".into())
            }),
        Platform::MacOs => sysenv::home_dir(platform, env)
            .map(|home| {
                home.join("Library")
                    .join("Application Support")
                    .join("bifrost")
            })
            .ok_or_else(no_home),
        Platform::Linux => {
            let xdg = sysenv::non_empty(env, "XDG_CONFIG_HOME")
                .map(PathBuf::from)
                // The XDG spec says relative values must be ignored.
                .filter(|path| path.is_absolute());
            match xdg {
                Some(dir) => Ok(dir.join("bifrost")),
                None => sysenv::home_dir(platform, env)
                    .map(|home| home.join(".config").join("bifrost"))
                    .ok_or_else(no_home),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::sysenv::testing::{abs, fake_env};

    fn os(path: PathBuf) -> OsString {
        path.into_os_string()
    }

    #[test]
    fn override_wins_on_every_platform() {
        let env = fake_env(&[
            (CONFIG_DIR_VAR, os(abs("tmp/bifrost-test"))),
            ("XDG_CONFIG_HOME", os(abs("xdg"))),
            ("HOME", os(abs("home/rein"))),
            ("APPDATA", os(abs("appdata"))),
        ]);
        for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
            assert_eq!(
                config_dir_for(platform, &env).unwrap(),
                abs("tmp/bifrost-test"),
                "{platform:?}"
            );
        }
    }

    #[test]
    fn relative_override_is_rejected() {
        for relative in ["relative/dir", ".", "..", "bifrost"] {
            let env = fake_env(&[(CONFIG_DIR_VAR, OsString::from(relative))]);
            for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
                match config_dir_for(platform, &env) {
                    Err(StoreError::RelativeConfigDir(dir)) => {
                        assert_eq!(dir, PathBuf::from(relative))
                    }
                    other => panic!("{relative:?} on {platform:?}: {other:?}"),
                }
            }
        }
        let message = config_dir_for(
            Platform::Linux,
            &fake_env(&[(CONFIG_DIR_VAR, OsString::from("relative"))]),
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("must be an absolute path"), "{message}");
    }

    #[test]
    fn empty_override_is_ignored() {
        let env = fake_env(&[
            (CONFIG_DIR_VAR, OsString::new()),
            ("HOME", os(abs("home/rein"))),
        ]);
        assert_eq!(
            config_dir_for(Platform::Linux, &env).unwrap(),
            abs("home/rein").join(".config").join("bifrost")
        );
    }

    #[test]
    fn linux_uses_xdg_config_home_then_dot_config() {
        let env = fake_env(&[
            ("XDG_CONFIG_HOME", os(abs("xdg"))),
            ("HOME", os(abs("home/rein"))),
        ]);
        assert_eq!(
            config_dir_for(Platform::Linux, &env).unwrap(),
            abs("xdg").join("bifrost")
        );

        let env = fake_env(&[("HOME", os(abs("home/rein")))]);
        assert_eq!(
            config_dir_for(Platform::Linux, &env).unwrap(),
            abs("home/rein").join(".config").join("bifrost")
        );
    }

    #[test]
    fn linux_ignores_a_relative_xdg_config_home() {
        let env = fake_env(&[
            ("XDG_CONFIG_HOME", OsString::from("relative")),
            ("HOME", os(abs("home/rein"))),
        ]);
        assert_eq!(
            config_dir_for(Platform::Linux, &env).unwrap(),
            abs("home/rein").join(".config").join("bifrost")
        );
    }

    #[test]
    fn macos_uses_application_support() {
        let env = fake_env(&[("HOME", os(abs("Users/rein")))]);
        assert_eq!(
            config_dir_for(Platform::MacOs, &env).unwrap(),
            abs("Users/rein")
                .join("Library")
                .join("Application Support")
                .join("bifrost")
        );
    }

    #[test]
    fn windows_uses_appdata() {
        let env = fake_env(&[("APPDATA", os(abs("Users/rein/AppData/Roaming")))]);
        assert_eq!(
            config_dir_for(Platform::Windows, &env).unwrap(),
            abs("Users/rein/AppData/Roaming").join("bifrost")
        );
    }

    #[test]
    fn missing_variables_give_a_helpful_error() {
        let env = fake_env(&[]);
        for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
            let err = config_dir_for(platform, &env).unwrap_err();
            assert!(matches!(err, StoreError::NoConfigDir(_)), "{platform:?}");
            assert!(err.to_string().contains("BIFROST_CONFIG_DIR"), "{err}");
        }
    }
}
