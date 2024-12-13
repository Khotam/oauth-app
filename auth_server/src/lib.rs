use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use storage::Storage;
mod storage;

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

pub fn is_valid_credentials(creds: &Credentials) -> Result<bool, String> {
    let storage = Storage::get()?;
    let client = storage.clients.get(&creds.client_id);

    if let Some(client) = client {
        if let Some(client_secret) = &creds.client_secret {
            Ok(client.client_secret == *client_secret)
        } else {
            Ok(false)
        }
    } else {
        Ok(false)
    }
}
