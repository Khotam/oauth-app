use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

#[derive(Debug)]
pub struct Profile {
    pub name: String,
    pub email: String,
}

#[derive(Debug)]
pub struct User {
    pub username: String,
    pub password: String,
    pub profile: Profile,
}

#[derive(Debug)]
pub struct Token {
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires: DateTime<Utc>,
    pub is_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub scope: String,
    pub expires: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct Client {
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub name: String,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug)]
pub struct Storage {
    pub clients: HashMap<String, Client>,
    pub auth_codes: HashMap<String, AuthCode>,
    pub tokens: HashMap<String, Token>,
    pub users: HashMap<String, User>,
}

pub static MUTABLE_STORAGE: Lazy<Mutex<Storage>> = Lazy::new(|| {
    Mutex::new(Storage {
        clients: HashMap::new(),
        auth_codes: HashMap::new(),
        tokens: HashMap::new(),
        users: HashMap::new(),
    })
});

impl Storage {
    pub fn get() -> Result<MutexGuard<'static, Storage>, String> {
        return MUTABLE_STORAGE
            .lock()
            .map_err(|err| format!("Failed to acquire lock: {}", err));
    }
}
