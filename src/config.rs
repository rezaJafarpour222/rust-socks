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
    pub udp_relay_host: Option<String>,
    pub udp_relay_port_start: u16,
    pub udp_relay_port_count: usize,
}

impl AppConfig {
    pub fn from_env() -> Self {
        load_dotenv();

        let socks5_port = required_env("SOCKS5_PORT");
        let cache_duration_secs = required_parse("CACHE_DURATION_SECS");
        let cache_entry_limit = required_parse("CACHE_ENTRY_LIMIT");
        let cert_path = required_env("CERT_PATH");
        let key_path = required_env("KEY_PATH");
        let proxy_username = env::var("PROXY_USERNAME").ok().filter(|s| !s.is_empty());
        let proxy_password = env::var("PROXY_PASSWORD").ok().filter(|s| !s.is_empty());
        let udp_relay_host = env::var("UDP_RELAY_HOST").ok().filter(|s| !s.is_empty());
        let udp_relay_port_start = env::var("UDP_RELAY_PORT_START")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        let udp_relay_port_count = env::var("UDP_RELAY_PORT_COUNT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);

        let config = Self {
            socks5_port,
            cache_duration_secs,
            cache_entry_limit,
            cert_path,
            key_path,
            proxy_username,
            proxy_password,
            udp_relay_host,
            udp_relay_port_start,
            udp_relay_port_count,
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

    pub fn udp_relay_ports(&self) -> Vec<u16> {
        if self.udp_relay_port_count == 0 {
            return Vec::new();
        }

        (0..self.udp_relay_port_count)
            .filter_map(|offset| {
                self.udp_relay_port_start
                    .checked_add(offset as u16)
            })
            .collect()
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

        if self.udp_relay_port_count > 0 && self.udp_relay_port_start == 0 {
            panic!("UDP_RELAY_PORT_START must be set when UDP_RELAY_PORT_COUNT is greater than zero");
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

fn required_env(key: &str) -> String {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!("{key} must be set"),
    }
}

fn required_parse<T>(key: &str) -> T
where
    T: std::str::FromStr,
{
    let value = required_env(key);
    value.parse().unwrap_or_else(|_| panic!("{key} must be a valid number"))
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