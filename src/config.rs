/// Configuration loading and management for the application.
///
/// This module handles loading, parsing, and validating configuration settings
/// from a YAML configuration file or environment variables. It provides strongly typed access to
/// application settings for server properties, Ollama API integration,
/// and security services.
///
/// # Configuration Flow
///
/// 1. Load configuration from YAML file or environment variables
/// 2. Parse into structured types
/// 3. Validate all required settings
/// 4. Make configuration available to application components
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info};

/// Errors that can occur when loading or validating configuration.
///
/// This enum encapsulates the various failure modes when dealing with
/// configuration, including file access errors, YAML parsing issues,
/// and validation of configuration values.
#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum ConfigError {
    /// File I/O errors when reading the configuration file
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    /// YAML parsing errors in the configuration file
    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] serde_yml::Error),

    /// Configuration validation errors
    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// Root configuration structure containing all application settings.
///
/// This structure is the top-level container for all configuration settings
/// used by the application, organized into logical sections.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Server configuration settings
    pub server: ServerConfig,

    /// Ollama API integration settings
    pub ollama: OllamaConfig,

    /// Security and content filtering settings
    pub security: SecurityConfig,
}

/// Server configuration settings.
///
/// Controls how the proxy server listens for connections and processes requests.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// IP address to bind the server to
    pub host: String,

    /// Port number to listen on
    pub port: u16,

    /// Logging level (e.g., "INFO", "DEBUG", "ERROR")
    pub debug_level: String,
}

/// Ollama API integration settings.
///
/// Configuration for connecting to and interacting with the Ollama API service.
#[derive(Debug, Clone, Deserialize)]
pub struct OllamaConfig {
    /// Base URL of the Ollama API service
    pub base_url: String,
}

/// Security and content filtering settings.
///
/// Configuration for connecting to the PANW AI Runtime security service
/// and setting up content security scanning.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Base URL of the PANW AI Runtime security API
    pub base_url: String,

    /// API key for authenticating with the security service
    pub api_key: String,

    /// Security profile name to use for assessments
    pub profile_name: String,

    /// Application name for telemetry and audit
    pub app_name: String,

    /// Application user identifier
    pub app_user: String,

    /// Context for grounding LLM responses. When not empty, contextual grounding is enabled.
    #[serde(default)]
    pub contextual_grounding: String,
}

/// Loads configuration from environment variables.
///
/// This function reads configuration values from environment variables,
/// falling back to default values where appropriate.
///
/// # Returns
///
/// * `Config` - Configuration object populated from environment variables
fn load_from_env() -> Config {
    info!("Loading configuration from environment variables");

    let server = ServerConfig {
        host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        port: env::var("SERVER_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(11435),
        debug_level: env::var("SERVER_DEBUG_LEVEL").unwrap_or_else(|_| "INFO".to_string()),
    };

    let ollama = OllamaConfig {
        base_url: env::var("OLLAMA_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:11434".to_string()),
    };

    let security = SecurityConfig {
        base_url: env::var("SECURITY_BASE_URL")
            .unwrap_or_else(|_| "https://service.api.aisecurity.paloaltonetworks.com".to_string()),
        api_key: env::var("SECURITY_API_KEY").unwrap_or_default(),
        profile_name: env::var("SECURITY_PROFILE_NAME").unwrap_or_default(),
        app_name: env::var("SECURITY_APP_NAME").unwrap_or_else(|_| "panw-api-ollama".to_string()),
        app_user: env::var("SECURITY_APP_USER").unwrap_or_else(|_| "default".to_string()),
        contextual_grounding: env::var("SECURITY_CONTEXTUAL_GROUNDING_CONTEXT").unwrap_or_default(),
    };

    Config {
        server,
        ollama,
        security,
    }
}

/// Loads configuration from a YAML file or environment variables.
///
/// This function first attempts to load configuration from the specified file path.
/// If the file doesn't exist or can't be read, it falls back to using environment variables.
/// In either case, the resulting configuration is validated before being returned.
///
/// # Arguments
///
/// * `path` - Path to the YAML configuration file (optional, will use env vars if file not found)
///
/// # Returns
///
/// * `Ok(Config)` - Validated configuration object
/// * `Err(ConfigError)` - If loading or validation fails
///
/// # Example
///
/// ```
/// let config = config::load_config("config.yaml")?;
/// println!("Server will listen on {}:{}", config.server.host, config.server.port);
/// ```
pub fn load_config(path: &str) -> Result<Config, ConfigError> {
    // Check if file exists
    if Path::new(path).exists() {
        info!("Loading configuration from file: {}", path);

        // Read file content
        let content = fs::read_to_string(path)?;
        debug!("Successfully read configuration file");

        // Parse YAML
        let mut config: Config = serde_yml::from_str(&content)?;
        debug!("Successfully parsed YAML configuration");

        // Override with environment variables if present
        override_with_env(&mut config);

        // Validate configuration
        config.validate()?;
        info!("Configuration validated successfully");

        Ok(config)
    } else {
        info!(
            "Configuration file not found: {}. Using environment variables.",
            path
        );
        let config = load_from_env();
        config.validate()?;
        info!("Configuration from environment variables validated successfully");
        Ok(config)
    }
}

/// Override configuration values with environment variables if present
fn override_with_env(config: &mut Config) {
    if let Ok(host) = env::var("SERVER_HOST") {
        config.server.host = host;
    }

    if let Ok(port) = env::var("SERVER_PORT") {
        if let Ok(port) = port.parse() {
            config.server.port = port;
        }
    }

    if let Ok(debug_level) = env::var("SERVER_DEBUG_LEVEL") {
        config.server.debug_level = debug_level;
    }

    if let Ok(base_url) = env::var("OLLAMA_BASE_URL") {
        config.ollama.base_url = base_url;
    }

    if let Ok(base_url) = env::var("SECURITY_BASE_URL") {
        config.security.base_url = base_url;
    }

    if let Ok(api_key) = env::var("SECURITY_API_KEY") {
        config.security.api_key = api_key;
    }

    if let Ok(profile_name) = env::var("SECURITY_PROFILE_NAME") {
        config.security.profile_name = profile_name;
    }

    if let Ok(app_name) = env::var("SECURITY_APP_NAME") {
        config.security.app_name = app_name;
    }

    if let Ok(app_user) = env::var("SECURITY_APP_USER") {
        config.security.app_user = app_user;
    }

    // Load contextual grounding configuration
    if let Ok(contextual_grounding) = env::var("SECURITY_CONTEXTUAL_GROUNDING_CONTEXT") {
        config.security.contextual_grounding = contextual_grounding;
    }
}

impl Config {
    /// Validates all configuration settings.
    ///
    /// This method checks that all required configuration values are present
    /// and valid, returning an error if any validation fails.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all validation checks pass
    /// * `Err(ConfigError)` - If any validation check fails
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate server config
        if self.server.host.is_empty() {
            return Err(ConfigError::ValidationError(
                "Server host cannot be empty".into(),
            ));
        }

        // Validate ollama config
        if self.ollama.base_url.is_empty() {
            return Err(ConfigError::ValidationError(
                "Ollama base URL cannot be empty".into(),
            ));
        }

        // Ensure Ollama URL is properly formatted
        if !self.ollama.base_url.starts_with("http") {
            return Err(ConfigError::ValidationError(
                "Ollama base URL must start with http:// or https://".into(),
            ));
        }

        // Validate security config - API credentials
        if self.security.base_url.is_empty() || self.security.api_key.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security credentials missing (base_url or api_key)".into(),
            ));
        }

        // Ensure security URL is properly formatted
        if !self.security.base_url.starts_with("http") {
            return Err(ConfigError::ValidationError(
                "Security base URL must start with http:// or https://".into(),
            ));
        }

        // Validate PANW AI profile config
        if self.security.profile_name.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security profile_name is required".into(),
            ));
        }

        if self.security.app_name.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security app_name is required".into(),
            ));
        }

        if self.security.app_user.is_empty() {
            return Err(ConfigError::ValidationError(
                "Security app_user is required".into(),
            ));
        }

        Ok(())
    }
}
