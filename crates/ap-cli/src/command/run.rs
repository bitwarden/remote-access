//! Run subcommand — fetch a credential and inject it as env vars into a child process
//!
//! Secrets never touch stdout or disk; they are passed exclusively through
//! the child process's environment.

use std::collections::HashMap;

use ap_client::CredentialData;
use clap::Args;
use color_eyre::eyre::{Result, bail};

use super::DEFAULT_PROXY_URL;
use super::connect::fetch_credential;
use super::output::{exit_code, exit_code_for_error};

/// All credential fields with their canonical names and AAC_ env var keys.
const CREDENTIAL_FIELDS: &[(&str, &str)] = &[
    ("username", "AAC_USERNAME"),
    ("password", "AAC_PASSWORD"),
    ("totp", "AAC_TOTP"),
    ("uri", "AAC_URI"),
    ("notes", "AAC_NOTES"),
    ("domain", "AAC_DOMAIN"),
    ("credential_id", "AAC_CREDENTIAL_ID"),
];

/// Run a command with credentials injected as environment variables
#[derive(Args)]
#[command(after_help = "\
EXAMPLES:
  # Map specific fields to env vars:
  aac run --domain example.com --env DB_PASSWORD=password --env DB_USER=username -- psql

  # Inject all fields with AAC_ prefix:
  aac run --domain example.com --env-all -- deploy.sh

  # Combine defaults with custom overrides:
  aac run --domain example.com --env-all --env CUSTOM_PW=password -- deploy.sh

The token can be passed via --token <TOKEN> or the AAC_TOKEN env var.

VALID FIELDS: username, password, totp, uri, notes, domain, credential_id")]
pub struct RunArgs {
    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Domain to request credentials for
    #[arg(long, conflicts_with = "id")]
    pub domain: Option<String>,

    /// Vault item ID to request credentials for
    #[arg(long, conflicts_with = "domain")]
    pub id: Option<String>,

    /// Token (rendezvous code or PSK token)
    #[arg(long, env = "AAC_TOKEN", conflicts_with = "session")]
    pub token: Option<String>,

    /// Session fingerprint to reconnect to
    #[arg(long, conflicts_with = "token")]
    pub session: Option<String>,

    /// Don't save this connection for future use
    #[arg(long)]
    pub ephemeral_connection: bool,

    /// Map a credential field to an env var: VAR_NAME=field
    /// Valid fields: username, password, totp, uri, notes, domain, credential_id
    #[arg(long = "env", value_name = "VAR=FIELD")]
    pub env_mappings: Vec<String>,

    /// Inject all credential fields with AAC_ prefix
    #[arg(long = "env-all")]
    pub env_all: bool,

    /// Command and arguments to run (after --)
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

/// Look up a credential field value by name
fn get_field<'a>(credential: &'a CredentialData, field: &str) -> Option<&'a str> {
    match field {
        "username" => credential.username.as_deref(),
        "password" => credential.password.as_deref(),
        "totp" => credential.totp.as_deref(),
        "uri" => credential.uri.as_deref(),
        "notes" => credential.notes.as_deref(),
        "credential_id" => credential.credential_id.as_deref(),
        "domain" => credential.domain.as_deref(),
        _ => None,
    }
}

/// Build the environment variable map from credential data and mapping options.
fn build_env_vars(
    credential: &CredentialData,
    env_all: bool,
    explicit_mappings: &[(String, String)],
) -> HashMap<String, String> {
    let mut env_vars = HashMap::new();

    if env_all {
        for &(field_name, env_key) in CREDENTIAL_FIELDS {
            if let Some(value) = get_field(credential, field_name) {
                env_vars.insert(env_key.to_string(), value.to_string());
            }
        }
    }

    // Apply explicit mappings (override any --env-all defaults)
    for (var_name, field) in explicit_mappings {
        if let Some(value) = get_field(credential, field) {
            env_vars.insert(var_name.clone(), value.to_string());
        }
    }

    env_vars
}

/// Check whether a field name is valid.
fn is_valid_field(field: &str) -> bool {
    CREDENTIAL_FIELDS.iter().any(|&(name, _)| name == field)
}

impl RunArgs {
    pub async fn run(self) -> Result<()> {
        // Validate that exactly one of --domain or --id is provided
        let query = match (&self.domain, &self.id) {
            (Some(domain), None) => ap_client::CredentialQuery::Domain(domain.clone()),
            (None, Some(id)) => ap_client::CredentialQuery::Id(id.clone()),
            (None, None) => bail!("Either --domain or --id is required"),
            (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents this"),
        };

        // Validate that at least one env mapping method is specified
        if !self.env_all && self.env_mappings.is_empty() {
            bail!("At least one of --env or --env-all is required");
        }

        // Parse and validate --env mappings up front
        let mut explicit_mappings: Vec<(String, String)> = Vec::new();
        for mapping in &self.env_mappings {
            let (var_name, field) = mapping.split_once('=').ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "Invalid --env format: '{mapping}' (expected VAR_NAME=field)"
                )
            })?;

            if var_name.is_empty() {
                bail!("Empty variable name in --env mapping: '{mapping}'");
            }

            let field_lower = field.to_lowercase();
            if !is_valid_field(&field_lower) {
                let valid: Vec<&str> = CREDENTIAL_FIELDS.iter().map(|&(name, _)| name).collect();
                bail!(
                    "Unknown credential field '{field}' in --env mapping. \
                     Valid fields: {}",
                    valid.join(", ")
                );
            }

            explicit_mappings.push((var_name.to_string(), field_lower));
        }

        // Fetch the credential
        let credential = match fetch_credential(
            &self.proxy_url,
            self.token.as_deref(),
            self.session.as_deref(),
            self.ephemeral_connection,
            &query,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                let code = e
                    .downcast_ref::<ap_client::ClientError>()
                    .map(exit_code_for_error)
                    .unwrap_or(exit_code::GENERAL_ERROR);
                tracing::error!("{e}");
                std::process::exit(code);
            }
        };

        let env_vars = build_env_vars(&credential, self.env_all, &explicit_mappings);

        if env_vars.is_empty() {
            tracing::warn!(
                "No credential fields matched — child process will run without injected env vars"
            );
        }

        // Spawn child process
        let program = &self.command[0];
        let args = &self.command[1..];

        let status = std::process::Command::new(program)
            .args(args)
            .envs(&env_vars)
            .status()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to execute '{program}': {e}"))?;

        std::process::exit(status.code().unwrap_or(exit_code::GENERAL_ERROR));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_credential() -> CredentialData {
        CredentialData {
            username: Some("admin".to_string()),
            password: Some("s3cret".to_string()),
            totp: Some("123456".to_string()),
            uri: Some("https://example.com".to_string()),
            notes: None,
            credential_id: Some("item-uuid-123".to_string()),
            domain: Some("example.com".to_string()),
        }
    }

    #[test]
    fn get_field_returns_correct_values() {
        let cred = make_credential();
        assert_eq!(get_field(&cred, "username"), Some("admin"));
        assert_eq!(get_field(&cred, "password"), Some("s3cret"));
        assert_eq!(get_field(&cred, "totp"), Some("123456"));
        assert_eq!(get_field(&cred, "domain"), Some("example.com"));
        assert_eq!(get_field(&cred, "notes"), None);
        assert_eq!(get_field(&cred, "credential_id"), Some("item-uuid-123"));
        assert_eq!(get_field(&cred, "invalid"), None);
    }

    #[test]
    fn build_env_vars_with_env_all() {
        let cred = make_credential();
        let env_vars = build_env_vars(&cred, true, &[]);

        assert_eq!(env_vars.get("AAC_USERNAME").expect("username"), "admin");
        assert_eq!(env_vars.get("AAC_PASSWORD").expect("password"), "s3cret");
        assert_eq!(env_vars.get("AAC_TOTP").expect("totp"), "123456");
        assert_eq!(env_vars.get("AAC_URI").expect("uri"), "https://example.com");
        assert!(!env_vars.contains_key("AAC_NOTES"), "notes is None");
        assert_eq!(env_vars.get("AAC_DOMAIN").expect("domain"), "example.com");
        assert_eq!(
            env_vars.get("AAC_CREDENTIAL_ID").expect("credential_id"),
            "item-uuid-123"
        );
        assert_eq!(env_vars.len(), 6);
    }

    #[test]
    fn build_env_vars_with_explicit_mappings() {
        let cred = make_credential();
        let mappings = vec![
            ("DB_USER".to_string(), "username".to_string()),
            ("DB_PASS".to_string(), "password".to_string()),
        ];
        let env_vars = build_env_vars(&cred, false, &mappings);

        assert_eq!(env_vars.get("DB_USER").expect("DB_USER"), "admin");
        assert_eq!(env_vars.get("DB_PASS").expect("DB_PASS"), "s3cret");
        assert_eq!(env_vars.len(), 2);
    }

    #[test]
    fn build_env_vars_explicit_overrides_env_all() {
        let cred = make_credential();
        let mappings = vec![("AAC_USERNAME".to_string(), "password".to_string())];
        let env_vars = build_env_vars(&cred, true, &mappings);

        // Explicit mapping overrides the AAC_USERNAME from env_all
        assert_eq!(env_vars.get("AAC_USERNAME").expect("overridden"), "s3cret");
    }

    #[test]
    fn build_env_vars_env_all_empty_credential() {
        let cred = CredentialData {
            username: None,
            password: None,
            totp: None,
            uri: None,
            notes: None,
            credential_id: None,
            domain: Some("example.com".to_string()),
        };
        let env_vars = build_env_vars(&cred, true, &[]);

        assert_eq!(env_vars.len(), 1);
        assert_eq!(env_vars.get("AAC_DOMAIN").expect("domain"), "example.com");
    }

    #[test]
    fn is_valid_field_accepts_known_rejects_unknown() {
        assert!(is_valid_field("username"));
        assert!(is_valid_field("credential_id"));
        assert!(is_valid_field("domain"));
        assert!(!is_valid_field("bogus"));
        assert!(!is_valid_field(""));
    }
}
