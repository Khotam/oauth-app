use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

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

#[derive(Deserialize)]
pub struct LoginQueryParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
}

#[derive(Deserialize, Debug)]
pub struct OauthTokenParams {
    pub auth_code: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub grant_type: String,
}

#[derive(Deserialize, Debug)]
pub struct TokenParams {
    pub access_token: String,
}

#[derive(Deserialize, Serialize)]
pub enum TokenStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Deserialize, Serialize)]
pub struct IntrospectResponse {
    pub expires: DateTime<Utc>,
    pub scope: String,
    pub status: TokenStatus,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TokenResponse {
    pub expires_in: i32,
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
    pub is_revoked: bool,
}

#[derive(Clone, Debug)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: Option<String>,
}

pub fn is_valid_credentials(creds: &Credentials) -> bool {
    let storage = MUTABLE_STORAGE.lock().unwrap();
    let client = storage.clients.get(&creds.client_id[..]);
    dbg!(client);
    dbg!(creds);

    match client {
        Some(cl) => {
            if creds.client_secret.is_some()
                && *creds.client_secret.as_ref().unwrap() != cl.client_secret
            {
                return false;
            }

            return true;
        }
        None => false,
    }
}
