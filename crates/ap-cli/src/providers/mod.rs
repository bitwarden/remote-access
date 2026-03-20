//! Credential provider abstraction
//!
//! Defines the [`CredentialProvider`] trait for pluggable password manager
//! backends, and ships the built-in [`BitwardenProvider`].

mod bitwarden;
mod example;

use ap_client::CredentialData;
pub use ap_client::CredentialQuery;
pub use bitwarden::BitwardenProvider;
pub use example::ExampleProvider;
use color_eyre::eyre::{Result, bail};

/// Current readiness of a credential provider.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ProviderStatus {
    /// Provider is ready to serve credentials.
    Ready { user_info: Option<String> },
    /// Provider requires an unlock step (e.g. master password or session key).
    Locked {
        prompt: String,
        user_info: Option<String>,
    },
    /// Provider is installed but not usable (e.g. not logged in).
    Unavailable { reason: String },
    /// Provider binary is not installed.
    NotInstalled { install_hint: String },
}

/// Result of a credential lookup.
#[derive(Debug)]
pub enum LookupResult {
    /// A credential was found.
    Found(CredentialData),
    /// No matching credential exists.
    NotFound,
    /// The provider is not ready (e.g. vault locked).
    NotReady { message: String },
}

/// A pluggable credential provider.
///
/// Implementations back different password managers (Bitwarden CLI, 1Password,
/// etc.) behind a uniform interface so the listen command can work with any of
/// them.
pub trait CredentialProvider: Send + Sync {
    /// Human-readable name shown in the TUI header (e.g. "Bitwarden").
    fn name(&self) -> &str;

    /// Check current readiness.
    fn status(&self) -> ProviderStatus;

    /// Attempt to unlock the provider.
    ///
    /// The semantics of `input` are provider-specific. For Bitwarden it may be
    /// a master password *or* a raw session key — the implementation
    /// auto-detects which.
    fn unlock(&mut self, input: &str) -> Result<(), String>;

    /// Look up a credential.
    fn lookup(&self, query: &CredentialQuery) -> LookupResult;
}

/// Create a provider by name.
pub fn create_provider(name: &str) -> Result<Box<dyn CredentialProvider>> {
    match name {
        "bitwarden" => Ok(Box::new(BitwardenProvider::new())),
        "example" => Ok(Box::new(ExampleProvider::new())),
        _ => bail!("Unknown credential provider: '{name}'. Available: bitwarden, example"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // -- Mock provider ------------------------------------------------------

    struct MockProvider {
        name: &'static str,
        status: ProviderStatus,
        credentials: HashMap<String, CredentialData>,
        unlock_result: Result<(), String>,
    }

    impl MockProvider {
        fn new() -> Self {
            Self {
                name: "Mock",
                status: ProviderStatus::Ready { user_info: None },
                credentials: HashMap::new(),
                unlock_result: Ok(()),
            }
        }

        fn with_credential(mut self, domain: &str, cred: CredentialData) -> Self {
            self.credentials.insert(domain.to_string(), cred);
            self
        }

        fn with_unlock_error(mut self, msg: &str) -> Self {
            self.unlock_result = Err(msg.to_string());
            self
        }
    }

    impl CredentialProvider for MockProvider {
        fn name(&self) -> &str {
            self.name
        }

        fn status(&self) -> ProviderStatus {
            match &self.status {
                ProviderStatus::Ready { user_info } => ProviderStatus::Ready {
                    user_info: user_info.clone(),
                },
                ProviderStatus::Locked { prompt, user_info } => ProviderStatus::Locked {
                    prompt: prompt.clone(),
                    user_info: user_info.clone(),
                },
                ProviderStatus::Unavailable { reason } => ProviderStatus::Unavailable {
                    reason: reason.clone(),
                },
                ProviderStatus::NotInstalled { install_hint } => ProviderStatus::NotInstalled {
                    install_hint: install_hint.clone(),
                },
            }
        }

        fn unlock(&mut self, _input: &str) -> Result<(), String> {
            self.unlock_result.clone()
        }

        fn lookup(&self, query: &CredentialQuery) -> LookupResult {
            match self.credentials.get(query.search_string()) {
                Some(cred) => LookupResult::Found(cred.clone()),
                None => LookupResult::NotFound,
            }
        }
    }

    // -- create_provider() --------------------------------------------------

    #[test]
    fn create_provider_bitwarden() {
        let provider = create_provider("bitwarden").expect("should create bitwarden provider");
        assert_eq!(provider.name(), "Bitwarden");
    }

    #[test]
    fn create_provider_unknown() {
        match create_provider("nonexistent") {
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("nonexistent"),
                    "error should mention the name: {msg}"
                );
            }
            Ok(_) => panic!("should fail for unknown provider"),
        }
    }

    #[test]
    fn create_provider_empty() {
        assert!(create_provider("").is_err());
    }

    // -- MockProvider / trait contract --------------------------------------

    fn sample_credential() -> CredentialData {
        CredentialData {
            username: Some("alice".into()),
            password: Some("s3cret".into()),
            totp: None,
            uri: Some("https://example.com".into()),
            notes: None,
            credential_id: Some("id-123".into()),
            domain: Some("example.com".into()),
        }
    }

    #[test]
    fn mock_lookup_found() {
        let provider = MockProvider::new().with_credential("example.com", sample_credential());
        match provider.lookup(&CredentialQuery::Domain("example.com".to_string())) {
            LookupResult::Found(cred) => {
                assert_eq!(cred.username.as_deref(), Some("alice"));
                assert_eq!(cred.password.as_deref(), Some("s3cret"));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn mock_lookup_not_found() {
        let provider = MockProvider::new();
        assert!(matches!(
            provider.lookup(&CredentialQuery::Domain("unknown.com".to_string())),
            LookupResult::NotFound
        ));
    }

    #[test]
    fn mock_unlock_success() {
        let mut provider = MockProvider::new();
        assert!(provider.unlock("anything").is_ok());
    }

    #[test]
    fn mock_unlock_error() {
        let mut provider = MockProvider::new().with_unlock_error("vault sealed");
        let err = provider.unlock("anything").unwrap_err();
        assert_eq!(err, "vault sealed");
    }

    #[test]
    fn mock_name() {
        let provider = MockProvider::new();
        assert_eq!(provider.name(), "Mock");
    }

    #[test]
    fn mock_status_ready() {
        let provider = MockProvider::new();
        assert!(matches!(provider.status(), ProviderStatus::Ready { .. }));
    }
}
