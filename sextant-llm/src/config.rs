//! Provider selection, credential discovery, and provider settings.
//!
//! Secrets come only from the environment or a configuration file, never from a
//! command-line flag (FR-40). This module has no API that accepts a key as an
//! argument originating from a flag: credentials are read through an
//! [`EnvSource`], which the CLI backs with a [`LayeredEnv`] of the process
//! environment over an optional key=value config file. Non-secret settings
//! such as the model identifier are read the same way, below any explicit
//! value the caller passes (flags, then environment, then config file).

use std::collections::HashMap;
use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::LlmError;

/// Environment variable naming a Sextant config file that may hold provider
/// secrets as `KEY=VALUE` lines (FR-40). Process environment values still win
/// when both are set.
pub const SEXTANT_CONFIG_ENV: &str = "SEXTANT_CONFIG";

/// Setting for the Anthropic effort level (`output_config.effort`): one of
/// `low`, `medium`, `high`, `xhigh`, or `max`, or `off` (the default) to leave
/// the field out and use the model's own default, which every model accepts.
pub const ANTHROPIC_EFFORT_ENV: &str = "SEXTANT_ANTHROPIC_EFFORT";

/// Setting for Anthropic server-side refusal fallbacks: `on` (the default) or
/// `off`. When on, a request the first model declines can be re-run on another
/// Anthropic model within the same call.
pub const ANTHROPIC_FALLBACKS_ENV: &str = "SEXTANT_ANTHROPIC_FALLBACKS";

/// The largest config file Sextant reads. A `KEY=VALUE` secrets file is tiny,
/// so anything larger is a mistake or an attack, not configuration.
pub const MAX_CONFIG_FILE_BYTES: u64 = 64 * 1024;

/// The providers Sextant knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    /// Anthropic Messages API (first-class, feature `anthropic`).
    Anthropic,
    /// OpenAI chat completions (first-class, feature `openai`).
    OpenAi,
    /// A local Ollama server (optional, feature `ollama`).
    Ollama,
    /// The in-process mock used by tests; never auto-detected.
    Mock,
}

impl ProviderKind {
    /// The network providers, in auto-detection priority order. The mock is
    /// deliberately excluded: it is only ever selected explicitly by a test.
    pub const NETWORK_PROVIDERS: [ProviderKind; 3] = [
        ProviderKind::Anthropic,
        ProviderKind::OpenAi,
        ProviderKind::Ollama,
    ];

    /// The environment variable that supplies this provider's credential.
    ///
    /// For Anthropic and OpenAI this is the API key. For Ollama, which needs no
    /// key, it is the server host; its presence signals intent to use Ollama
    /// during auto-detection.
    pub fn credential_env_var(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "ANTHROPIC_API_KEY",
            ProviderKind::OpenAi => "OPENAI_API_KEY",
            ProviderKind::Ollama => "OLLAMA_HOST",
            ProviderKind::Mock => "SEXTANT_MOCK",
        }
    }

    /// Whether this provider authenticates with an API key, so an explicit
    /// request for it fails without one. Ollama needs no key.
    pub fn requires_credential(self) -> bool {
        matches!(self, ProviderKind::Anthropic | ProviderKind::OpenAi)
    }

    /// The environment variable (or config file key) that selects this
    /// provider's model when the caller does not pass one explicitly.
    pub fn model_env_var(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "SEXTANT_ANTHROPIC_MODEL",
            ProviderKind::OpenAi => "SEXTANT_OPENAI_MODEL",
            ProviderKind::Ollama => "SEXTANT_OLLAMA_MODEL",
            ProviderKind::Mock => "SEXTANT_MOCK_MODEL",
        }
    }

    /// The built-in default model identifier, used when neither the caller nor
    /// the configuration names one.
    ///
    /// Ollama has no default: a local server only serves the models its owner
    /// pulled, so the model must be configured through
    /// [`Self::model_env_var`].
    pub fn default_model(self) -> Option<&'static str> {
        match self {
            ProviderKind::Anthropic => Some("claude-opus-5"),
            ProviderKind::OpenAi => Some("gpt-6-luna"),
            ProviderKind::Ollama => None,
            ProviderKind::Mock => Some("mock"),
        }
    }

    /// Whether this provider was compiled into the current build. The mock is
    /// always present; the network providers depend on their feature flags.
    pub fn is_compiled_in(self) -> bool {
        match self {
            ProviderKind::Mock => true,
            ProviderKind::Anthropic => cfg!(feature = "anthropic"),
            ProviderKind::OpenAi => cfg!(feature = "openai"),
            ProviderKind::Ollama => cfg!(feature = "ollama"),
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::OpenAi => "openai",
            ProviderKind::Ollama => "ollama",
            ProviderKind::Mock => "mock",
        };
        f.write_str(name)
    }
}

impl FromStr for ProviderKind {
    type Err = LlmError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "anthropic" => Ok(ProviderKind::Anthropic),
            "openai" => Ok(ProviderKind::OpenAi),
            "ollama" => Ok(ProviderKind::Ollama),
            "mock" => Ok(ProviderKind::Mock),
            other => Err(LlmError::Config(format!(
                "unknown provider `{}`: expected anthropic, openai, or ollama",
                crate::sanitize::for_display(other)
            ))),
        }
    }
}

/// A source of configuration secrets and settings.
///
/// Backed by the process environment in production and by an in-memory map in
/// tests. Centralizing credential lookup here is what lets the crate guarantee
/// that no key is ever read from a flag (FR-40).
pub trait EnvSource {
    /// Return the value of a configuration variable, if present.
    fn get(&self, key: &str) -> Option<String>;
}

/// The real process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

impl EnvSource for HashMap<String, String> {
    fn get(&self, key: &str) -> Option<String> {
        HashMap::get(self, key).cloned()
    }
}

/// A `KEY=VALUE` config file used as a secondary secret source (FR-40).
///
/// Lines that are empty or start with `#` are ignored, a leading UTF-8 byte
/// order mark is ignored, and values may be wrapped in single or double quotes.
/// The file is optional: a missing file yields an empty source, so callers can
/// always layer it under the process environment. Any other problem is an
/// error rather than a silently empty source: a file that cannot be read, is
/// not a regular file, is larger than [`MAX_CONFIG_FILE_BYTES`], or is not
/// UTF-8. On Unix a file that grants any permission to its group or to others
/// is refused, because it holds API keys; restrict it with `chmod 600`. Other
/// platforms have no such check.
#[derive(Debug, Clone, Default)]
pub struct ConfigFileSource {
    values: HashMap<String, String>,
    /// Path that was loaded, when any, for diagnostics.
    pub path: Option<PathBuf>,
}

impl ConfigFileSource {
    /// Load `KEY=VALUE` pairs from `path`. A missing file yields an empty
    /// source. A symlink is followed, so a config managed as a dotfile link
    /// works; the checks apply to the file it points at.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::Config`] when the file exists but cannot be used:
    /// it cannot be read, is not a regular file, is too large, is not UTF-8,
    /// or (on Unix) is accessible by its group or by others.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LlmError> {
        let path = path.as_ref();
        let text = match read_config_text(path) {
            Ok(Some(text)) => text,
            Ok(None) => String::new(),
            Err(message) => {
                return Err(LlmError::Config(format!(
                    "config file {}: {message}",
                    path.display()
                )));
            }
        };
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        Ok(Self {
            values: parse_config_file(text),
            path: Some(path.to_path_buf()),
        })
    }

    /// Resolve the config path from `SEXTANT_CONFIG`, or the platform default
    /// when that variable is unset: `~/.config/sextant/config` on Unix, and
    /// `%APPDATA%\sextant\config` on Windows (falling back to
    /// `%USERPROFILE%\.config\sextant\config`, then to `HOME`).
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`Self::load`].
    pub fn from_default_location(env: &dyn EnvSource) -> Result<Self, LlmError> {
        if let Some(path) = env.get(SEXTANT_CONFIG_ENV).filter(|v| !v.trim().is_empty()) {
            return Self::load(path);
        }
        match default_config_path(env, cfg!(windows)) {
            Some(path) => Self::load(path),
            None => Ok(Self::default()),
        }
    }
}

impl EnvSource for ConfigFileSource {
    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }
}

/// The default config file location for the platform, or `None` when the
/// environment names no home or profile directory.
fn default_config_path(env: &dyn EnvSource, windows: bool) -> Option<PathBuf> {
    let non_empty = |key: &str| env.get(key).filter(|value| !value.trim().is_empty());
    if windows {
        if let Some(appdata) = non_empty("APPDATA") {
            return Some(PathBuf::from(appdata).join("sextant").join("config"));
        }
        if let Some(profile) = non_empty("USERPROFILE") {
            return Some(
                PathBuf::from(profile)
                    .join(".config")
                    .join("sextant")
                    .join("config"),
            );
        }
    }
    non_empty("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("sextant")
            .join("config")
    })
}

/// Read a config file's text, returning `Ok(None)` when it does not exist and
/// a short description of the problem otherwise.
fn read_config_text(path: &Path) -> Result<Option<String>, String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not read it: {error}")),
    };
    // Checked before opening: opening a FIFO for reading would block.
    if !metadata.is_file() {
        return Err("is not a regular file".to_owned());
    }
    check_private(&metadata)?;
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(format!(
            "is larger than the {MAX_CONFIG_FILE_BYTES}-byte limit"
        ));
    }
    let file = std::fs::File::open(path).map_err(|error| format!("could not open it: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read it: {error}"))?;
    if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
        return Err(format!(
            "is larger than the {MAX_CONFIG_FILE_BYTES}-byte limit"
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "is not valid UTF-8".to_owned())
}

/// Refuse a secrets file that its group or others can access (Unix only).
#[cfg(unix)]
fn check_private(metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "grants access to its group or to others (mode {mode:o}) but may hold API keys; \
             restrict it with `chmod 600`"
        ));
    }
    Ok(())
}

/// Non-Unix fallback: POSIX modes do not apply, so there is no check.
#[cfg(not(unix))]
fn check_private(_metadata: &std::fs::Metadata) -> Result<(), String> {
    Ok(())
}

/// Layer two secret sources: `primary` wins over `fallback` (FR-40).
///
/// Production wiring uses the process environment as primary and an optional
/// config file as fallback, so exported env vars override file contents.
#[derive(Debug, Clone)]
pub struct LayeredEnv<P, F> {
    /// Checked first (typically the process environment).
    pub primary: P,
    /// Checked when the primary has no value (typically a config file).
    pub fallback: F,
}

impl<P: EnvSource, F: EnvSource> EnvSource for LayeredEnv<P, F> {
    fn get(&self, key: &str) -> Option<String> {
        self.primary
            .get(key)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| self.fallback.get(key))
    }
}

/// Build the default production secret source: process env over config file.
///
/// # Errors
///
/// Returns [`LlmError::Config`] when a config file exists but cannot be used
/// (see [`ConfigFileSource::load`]).
pub fn default_secret_source() -> Result<LayeredEnv<ProcessEnv, ConfigFileSource>, LlmError> {
    let process = ProcessEnv;
    let file = ConfigFileSource::from_default_location(&process)?;
    Ok(LayeredEnv {
        primary: process,
        fallback: file,
    })
}

/// Parse a simple `KEY=VALUE` config body.
fn parse_config_file(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = strip_quotes(value.trim());
        values.insert(key.to_owned(), value.to_owned());
    }
    values
}

fn strip_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
}

/// Whether a provider's credential is present in the given environment.
fn credential_present(kind: ProviderKind, env: &dyn EnvSource) -> bool {
    env.get(kind.credential_env_var())
        .is_some_and(|value| !value.trim().is_empty())
}

/// The network providers that are both compiled in and have a credential
/// present, in priority order. For Ollama the "credential" is `OLLAMA_HOST`,
/// which signals intent to use a local server.
pub fn detect_available(env: &dyn EnvSource) -> Vec<ProviderKind> {
    ProviderKind::NETWORK_PROVIDERS
        .into_iter()
        .filter(|kind| kind.is_compiled_in() && credential_present(*kind, env))
        .collect()
}

/// Resolve which provider to use.
///
/// When `requested` is `Some`, that provider must be compiled in and, if it
/// authenticates with an API key, have its credential present. Ollama needs no
/// key, so requesting it explicitly is enough, and its host defaults to
/// loopback. When `requested` is `None`, the provider is auto-detected from
/// available credentials: exactly one is used, none is an error, and more than
/// one is ambiguous and must be disambiguated with `--provider` (PRD Section
/// 12).
pub fn resolve_provider(
    requested: Option<ProviderKind>,
    env: &dyn EnvSource,
) -> Result<ProviderKind, LlmError> {
    match requested {
        Some(ProviderKind::Mock) => Ok(ProviderKind::Mock),
        Some(kind) => {
            if !kind.is_compiled_in() {
                return Err(LlmError::ProviderUnavailable(kind));
            }
            if kind.requires_credential() && !credential_present(kind, env) {
                return Err(LlmError::MissingCredential {
                    provider: kind,
                    env_var: kind.credential_env_var(),
                });
            }
            Ok(kind)
        }
        None => {
            let available = detect_available(env);
            match available.len() {
                0 => Err(LlmError::NoProviderConfigured),
                1 => Ok(available[0]),
                _ => Err(LlmError::AmbiguousProvider { available }),
            }
        }
    }
}

/// Read a provider's credential from the environment, or report it missing.
/// Surrounding whitespace (for example a trailing newline) is removed.
///
/// Only the keyed provider builders (Anthropic and OpenAI) call this, so in a
/// build without either feature it is intentionally unused.
#[cfg_attr(not(any(feature = "anthropic", feature = "openai")), allow(dead_code))]
pub(crate) fn require_credential(
    kind: ProviderKind,
    env: &dyn EnvSource,
) -> Result<String, LlmError> {
    env.get(kind.credential_env_var())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(LlmError::MissingCredential {
            provider: kind,
            env_var: kind.credential_env_var(),
        })
}

/// A non-empty setting value, trimmed, or `None` when unset or blank.
pub(crate) fn setting(env: &dyn EnvSource, key: &str) -> Option<String> {
    env.get(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Resolve the model for `kind`: an explicit value first (for example a
/// future `--model` flag), then the provider's model setting, then the
/// built-in default.
///
/// # Errors
///
/// Returns [`LlmError::MissingModel`] when the provider has no default and no
/// model was given or configured.
pub(crate) fn resolve_model(
    kind: ProviderKind,
    explicit: Option<&str>,
    env: &dyn EnvSource,
) -> Result<String, LlmError> {
    if let Some(model) = explicit.map(str::trim).filter(|model| !model.is_empty()) {
        return Ok(model.to_owned());
    }
    if let Some(model) = setting(env, kind.model_env_var()) {
        return Ok(model);
    }
    kind.default_model()
        .map(str::to_owned)
        .ok_or(LlmError::MissingModel {
            provider: kind,
            env_var: kind.model_env_var(),
        })
}

/// Parse an on/off switch setting.
///
/// # Errors
///
/// Returns [`LlmError::Config`] naming `key` for any other value.
#[cfg_attr(not(feature = "anthropic"), allow(dead_code))]
pub(crate) fn parse_switch(key: &str, value: &str) -> Result<bool, LlmError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" | "default" => Ok(true),
        "off" | "false" | "no" | "0" | "none" => Ok(false),
        _ => Err(LlmError::Config(format!(
            "{key} must be `on` or `off` (got `{}`)",
            crate::sanitize::for_display(value)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// A unique temporary directory removed when the guard drops.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "sextant-llm-config-{tag}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }

        /// Write a config file with owner-only permissions.
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).expect("write config");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod");
            }
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn provider_kind_round_trips_through_string() {
        for kind in [
            ProviderKind::Anthropic,
            ProviderKind::OpenAi,
            ProviderKind::Ollama,
            ProviderKind::Mock,
        ] {
            let parsed: ProviderKind = kind.to_string().parse().expect("round-trips");
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn unknown_provider_name_is_an_error() {
        assert!("gemini".parse::<ProviderKind>().is_err());
    }

    #[test]
    fn no_credentials_means_no_provider() {
        let error = resolve_provider(None, &env(&[])).expect_err("nothing configured");
        assert!(matches!(error, LlmError::NoProviderConfigured));
    }

    #[test]
    fn requesting_uncompiled_provider_is_unavailable() {
        // Anthropic is compiled out in the default test build, so an explicit
        // request for it must surface as unavailable rather than a silent skip.
        if !ProviderKind::Anthropic.is_compiled_in() {
            let error = resolve_provider(Some(ProviderKind::Anthropic), &env(&[]))
                .expect_err("not compiled in");
            assert!(matches!(
                error,
                LlmError::ProviderUnavailable(ProviderKind::Anthropic)
            ));
        }
    }

    #[test]
    fn requesting_a_keyed_provider_without_its_key_is_an_error() {
        if ProviderKind::OpenAi.is_compiled_in() {
            let error =
                resolve_provider(Some(ProviderKind::OpenAi), &env(&[])).expect_err("no key");
            assert!(matches!(
                error,
                LlmError::MissingCredential {
                    env_var: "OPENAI_API_KEY",
                    ..
                }
            ));
        }
    }

    #[test]
    fn requesting_ollama_needs_no_host() {
        // Ollama has no key; its host defaults to loopback, so an explicit
        // request is enough.
        if ProviderKind::Ollama.is_compiled_in() {
            let kind = resolve_provider(Some(ProviderKind::Ollama), &env(&[]))
                .expect("ollama resolves without OLLAMA_HOST");
            assert_eq!(kind, ProviderKind::Ollama);
        }
    }

    #[test]
    fn mock_resolves_without_a_credential() {
        let kind =
            resolve_provider(Some(ProviderKind::Mock), &env(&[])).expect("mock is always ok");
        assert_eq!(kind, ProviderKind::Mock);
    }

    #[test]
    fn empty_credential_is_treated_as_absent() {
        let kind = resolve_provider(None, &env(&[("ANTHROPIC_API_KEY", "   ")]));
        assert!(matches!(kind, Err(LlmError::NoProviderConfigured)));
    }

    #[test]
    fn credentials_are_trimmed() {
        let key = require_credential(
            ProviderKind::Anthropic,
            &env(&[("ANTHROPIC_API_KEY", " sk-key\n")]),
        )
        .expect("present");
        assert_eq!(key, "sk-key");
    }

    #[test]
    fn model_resolution_prefers_explicit_then_setting_then_default() {
        let configured = env(&[("SEXTANT_ANTHROPIC_MODEL", " claude-sonnet-5 ")]);
        assert_eq!(
            resolve_model(
                ProviderKind::Anthropic,
                Some("claude-fable-5-1"),
                &configured
            )
            .expect("explicit"),
            "claude-fable-5-1"
        );
        assert_eq!(
            resolve_model(ProviderKind::Anthropic, None, &configured).expect("setting"),
            "claude-sonnet-5"
        );
        assert_eq!(
            resolve_model(ProviderKind::Anthropic, None, &env(&[])).expect("default"),
            "claude-opus-5"
        );
        assert_eq!(
            resolve_model(ProviderKind::OpenAi, None, &env(&[])).expect("default"),
            "gpt-6-luna"
        );
    }

    #[test]
    fn ollama_has_no_default_model_and_names_the_setting() {
        let error = resolve_model(ProviderKind::Ollama, None, &env(&[])).expect_err("required");
        assert!(matches!(
            error,
            LlmError::MissingModel {
                provider: ProviderKind::Ollama,
                env_var: "SEXTANT_OLLAMA_MODEL",
            }
        ));
        assert!(error.to_string().contains("SEXTANT_OLLAMA_MODEL"));
        assert_eq!(
            resolve_model(
                ProviderKind::Ollama,
                None,
                &env(&[("SEXTANT_OLLAMA_MODEL", "qwen3")])
            )
            .expect("configured"),
            "qwen3"
        );
    }

    #[test]
    fn switch_settings_parse_on_and_off() {
        assert!(parse_switch("K", "on").expect("on"));
        assert!(!parse_switch("K", " OFF ").expect("off"));
        let error = parse_switch("K", "sometimes").expect_err("unknown");
        assert!(matches!(error, LlmError::Config(message) if message.contains('K')));
    }

    #[test]
    fn config_file_supplies_secrets_when_env_is_empty() {
        let file = ConfigFileSource {
            values: env(&[("OPENAI_API_KEY", "from-file")]),
            path: None,
        };
        let layered = LayeredEnv {
            primary: env(&[]),
            fallback: file,
        };
        assert_eq!(layered.get("OPENAI_API_KEY").as_deref(), Some("from-file"));
    }

    #[test]
    fn process_env_wins_over_config_file() {
        let file = ConfigFileSource {
            values: env(&[("OPENAI_API_KEY", "from-file")]),
            path: None,
        };
        let layered = LayeredEnv {
            primary: env(&[("OPENAI_API_KEY", "from-env")]),
            fallback: file,
        };
        assert_eq!(layered.get("OPENAI_API_KEY").as_deref(), Some("from-env"));
    }

    #[test]
    fn parse_config_file_skips_comments_and_strips_quotes() {
        let values = parse_config_file(
            "# comment\nANTHROPIC_API_KEY=\"abc\"\n\nOLLAMA_HOST='http://127.0.0.1:11434'\n",
        );
        assert_eq!(
            values.get("ANTHROPIC_API_KEY").map(String::as_str),
            Some("abc")
        );
        assert_eq!(
            values.get("OLLAMA_HOST").map(String::as_str),
            Some("http://127.0.0.1:11434")
        );
    }

    #[test]
    fn a_missing_config_file_is_an_empty_source() {
        let dir = TempDir::new("missing");
        let source = ConfigFileSource::load(dir.0.join("absent")).expect("missing is fine");
        assert!(source.get("ANTHROPIC_API_KEY").is_none());
    }

    #[test]
    fn a_leading_byte_order_mark_is_ignored() {
        let dir = TempDir::new("bom");
        let path = dir.write("config", b"\xEF\xBB\xBFANTHROPIC_API_KEY=abc\n");
        let source = ConfigFileSource::load(&path).expect("loads");
        // Without stripping, the first key would be "\u{feff}ANTHROPIC_API_KEY".
        assert_eq!(source.get("ANTHROPIC_API_KEY").as_deref(), Some("abc"));
    }

    #[test]
    fn an_oversized_config_file_is_refused() {
        let dir = TempDir::new("big");
        let big = vec![b'#'; usize::try_from(MAX_CONFIG_FILE_BYTES).expect("fits") + 1];
        let path = dir.write("config", &big);
        let error = ConfigFileSource::load(&path).expect_err("too large");
        assert!(matches!(error, LlmError::Config(message) if message.contains("limit")));
    }

    #[test]
    fn a_directory_at_the_config_path_is_reported() {
        let dir = TempDir::new("dir");
        let error = ConfigFileSource::load(&dir.0).expect_err("not a file");
        assert!(matches!(error, LlmError::Config(_)));
    }

    #[test]
    fn a_non_utf8_config_file_is_reported() {
        let dir = TempDir::new("utf8");
        let path = dir.write("config", b"KEY=\xFF\xFE\n");
        let error = ConfigFileSource::load(&path).expect_err("not UTF-8");
        assert!(matches!(error, LlmError::Config(message) if message.contains("UTF-8")));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_config_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("perms");
        let path = dir.write("config", b"ANTHROPIC_API_KEY=abc\n");
        for mode in [0o640, 0o604, 0o644, 0o660] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let error = ConfigFileSource::load(&path).expect_err("too permissive");
            assert!(
                matches!(&error, LlmError::Config(message) if message.contains("chmod 600")),
                "mode {mode:o}: {error}"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(ConfigFileSource::load(&path).is_ok());
    }

    #[test]
    fn the_default_path_resolves_on_windows_and_unix() {
        let windows = env(&[
            ("APPDATA", r"C:\Users\a\AppData\Roaming"),
            ("USERPROFILE", r"C:\Users\a"),
        ]);
        assert_eq!(
            default_config_path(&windows, true),
            Some(
                PathBuf::from(r"C:\Users\a\AppData\Roaming")
                    .join("sextant")
                    .join("config")
            )
        );
        let profile_only = env(&[("USERPROFILE", r"C:\Users\a")]);
        assert_eq!(
            default_config_path(&profile_only, true),
            Some(
                PathBuf::from(r"C:\Users\a")
                    .join(".config")
                    .join("sextant")
                    .join("config")
            )
        );
        let unix = env(&[("HOME", "/home/a"), ("APPDATA", "ignored")]);
        assert_eq!(
            default_config_path(&unix, false),
            Some(
                PathBuf::from("/home/a")
                    .join(".config")
                    .join("sextant")
                    .join("config")
            )
        );
        assert_eq!(default_config_path(&env(&[]), true), None);
    }

    #[test]
    fn sextant_config_overrides_the_default_location() {
        let dir = TempDir::new("explicit");
        let path = dir.write("custom", b"OPENAI_API_KEY=from-explicit\n");
        let source = ConfigFileSource::from_default_location(&env(&[(
            SEXTANT_CONFIG_ENV,
            path.to_str().expect("utf-8 path"),
        )]))
        .expect("loads");
        assert_eq!(
            source.get("OPENAI_API_KEY").as_deref(),
            Some("from-explicit")
        );
    }
}
