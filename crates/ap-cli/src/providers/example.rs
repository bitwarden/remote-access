//! Example credential provider with hardcoded credentials.
//!
//! Ships a small set of demo credentials for testing without requiring an
//! external password manager. Useful for demos, integration testing, and
//! development.

use ap_client::CredentialData;

use super::{CredentialProvider, CredentialQuery, LookupResult, ProviderStatus};

/// An in-memory credential provider with example entries for
/// example.com, google.com, and github.com.
pub struct ExampleProvider {
    credentials: Vec<CredentialData>,
}

impl ExampleProvider {
    pub fn new() -> Self {
        Self {
            credentials: vec![
                CredentialData {
                    username: Some("alice@example.com".to_string()),
                    password: Some("ex@mple-p@ssw0rd!".to_string().into()),
                    totp: None,
                    uri: Some("https://example.com/login".to_string()),
                    notes: Some("Example account for testing".to_string()),
                    credential_id: Some("cred-example-001".to_string()),
                    domain: Some("example.com".to_string()),
                },
                CredentialData {
                    username: Some("example@gmail.com".to_string()),
                    password: Some("g00gle-s3cure!".to_string().into()),
                    totp: Some("JBSWY3DPEHPK3PXP".to_string()),
                    uri: Some("https://accounts.google.com".to_string()),
                    notes: None,
                    credential_id: Some("cred-google-001".to_string()),
                    domain: Some("google.com".to_string()),
                },
                CredentialData {
                    username: Some("example-dev".to_string()),
                    password: Some("gh-t0ken-abc123!".to_string().into()),
                    totp: Some("NBSWY3DP".to_string()),
                    uri: Some("https://github.com".to_string()),
                    notes: Some("GitHub developer account".to_string()),
                    credential_id: Some("cred-github-001".to_string()),
                    domain: Some("github.com".to_string()),
                },
            ],
        }
    }
}

impl CredentialProvider for ExampleProvider {
    fn name(&self) -> &str {
        "Example"
    }

    fn status(&self) -> ProviderStatus {
        ProviderStatus::Ready {
            user_info: Some("alice (example provider)".to_string()),
        }
    }

    fn unlock(&mut self, _input: &str) -> Result<(), String> {
        Ok(())
    }

    fn lookup(&self, query: &CredentialQuery) -> LookupResult {
        let result = match query {
            CredentialQuery::Domain(domain) => {
                let domain_lower = domain.to_lowercase();
                self.credentials.iter().find(|c| {
                    c.domain
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains(&domain_lower))
                })
            }
            CredentialQuery::Id(id) => self
                .credentials
                .iter()
                .find(|c| c.credential_id.as_ref().is_some_and(|cid| cid == id)),
            CredentialQuery::Search(term) => {
                let term_lower = term.to_lowercase();
                self.credentials.iter().find(|c| {
                    c.domain
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains(&term_lower))
                        || c.username
                            .as_ref()
                            .is_some_and(|u| u.to_lowercase().contains(&term_lower))
                        || c.uri
                            .as_ref()
                            .is_some_and(|u| u.to_lowercase().contains(&term_lower))
                })
            }
        };

        match result {
            Some(cred) => LookupResult::Found(cred.clone()),
            None => LookupResult::NotFound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_example_com() {
        let provider = ExampleProvider::new();
        let result = provider.lookup(&CredentialQuery::Domain("example.com".to_string()));
        match result {
            LookupResult::Found(cred) => {
                assert_eq!(cred.username.as_deref(), Some("alice@example.com"));
                assert_eq!(cred.domain.as_deref(), Some("example.com"));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn lookup_google_com() {
        let provider = ExampleProvider::new();
        let result = provider.lookup(&CredentialQuery::Domain("google.com".to_string()));
        match result {
            LookupResult::Found(cred) => {
                assert_eq!(cred.username.as_deref(), Some("example@gmail.com"));
                assert!(cred.totp.is_some(), "google should have TOTP");
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn lookup_github_com() {
        let provider = ExampleProvider::new();
        let result = provider.lookup(&CredentialQuery::Domain("github.com".to_string()));
        match result {
            LookupResult::Found(cred) => {
                assert_eq!(cred.username.as_deref(), Some("example-dev"));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn lookup_by_id() {
        let provider = ExampleProvider::new();
        let result = provider.lookup(&CredentialQuery::Id("cred-github-001".to_string()));
        match result {
            LookupResult::Found(cred) => {
                assert_eq!(cred.domain.as_deref(), Some("github.com"));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn lookup_by_search() {
        let provider = ExampleProvider::new();
        let result = provider.lookup(&CredentialQuery::Search("example-dev".to_string()));
        match result {
            LookupResult::Found(cred) => {
                assert_eq!(cred.domain.as_deref(), Some("github.com"));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn lookup_not_found() {
        let provider = ExampleProvider::new();
        let result = provider.lookup(&CredentialQuery::Domain("unknown.com".to_string()));
        assert!(matches!(result, LookupResult::NotFound));
    }

    #[test]
    fn lookup_case_insensitive() {
        let provider = ExampleProvider::new();
        let result = provider.lookup(&CredentialQuery::Domain("GITHUB.COM".to_string()));
        assert!(matches!(result, LookupResult::Found(_)));
    }

    #[test]
    fn status_always_ready() {
        let provider = ExampleProvider::new();
        assert!(matches!(provider.status(), ProviderStatus::Ready { .. }));
    }

    #[test]
    fn unlock_always_succeeds() {
        let mut provider = ExampleProvider::new();
        assert!(provider.unlock("anything").is_ok());
    }
}
