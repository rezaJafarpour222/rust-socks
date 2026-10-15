use std::{env, fs, path::Path};

#[derive(Clone)]
pub struct AppConfig {
    pub socks5_port: String,
    pub cache_duration_secs: u64,
    pub cache_entry_limit: usize,
    pub cert_path: String,
    pub key_path: String,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Self {
        load_dotenv();

        let socks5_port = env_or("SOCKS5_PORT", "0.0.0.0:3000");
        let cache_duration_secs = parse_or("CACHE_DURATION_SECS", 24 * 60 * 60);
        let cache_entry_limit = parse_or("CACHE_ENTRY_LIMIT", 10_000);
        let cert_path = env_or("CERT_PATH", "certs/cert.pem");
        let key_path = env_or("KEY_PATH", "certs/key.pem");
        let proxy_username = env::var("PROXY_USERNAME").ok().filter(|s| !s.is_empty());
        let proxy_password = env::var("PROXY_PASSWORD").ok().filter(|s| !s.is_empty());

        let config = Self {
            socks5_port,
            cache_duration_secs,
            cache_entry_limit,
            cert_path,
            key_path,
            proxy_username,
            proxy_password,
        };

        config.validate();
        config
    }

    pub fn credentials(&self) -> Option<(String, String)> {
        match (self.proxy_username.clone(), self.proxy_password.clone()) {
            (Some(username), Some(password)) => Some((username, password)),
            _ => None,
        }
    }

    fn validate(&self) {
        if self.socks5_port.is_empty() {
            panic!("SOCKS5_PORT must not be empty");
        }

        if self.cert_path.is_empty() || self.key_path.is_empty() {
            panic!("CERT_PATH and KEY_PATH must not be empty");
        }

        if self.proxy_username.is_some() != self.proxy_password.is_some() {
            panic!("PROXY_USERNAME and PROXY_PASSWORD must be set together");
        }
    }

    pub fn apply_credentials_to_env(&self) {
        if let (Some(username), Some(password)) =
            (&self.proxy_username, &self.proxy_password)
        {
            unsafe { env::set_var("PROXY_USERNAME", username) };
            unsafe { env::set_var("PROXY_PASSWORD", password) };
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string())
}

fn parse_or<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

pub fn load_dotenv() {
    let path = Path::new(".env");
    if !path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"').trim_matches('\'');

                if !key.is_empty() && env::var(key).is_err() {
                    unsafe { env::set_var(key, value) };
                }
            }
        }
    }
}