use serde::{Deserialize, Serialize};

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
    // pub response_type: String,
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

#[derive(Deserialize, Serialize, Debug)]
pub struct TokenResponse {
    pub expires_in: i64,
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
    pub is_revoked: bool,
}
