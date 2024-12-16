use serde::Deserialize;

pub struct Config {
    pub client_id: &'static str,
    pub client_secret: &'static str,
    pub redirect_uri: &'static str,
    pub auth_server_url: &'static str,
    pub resource_server_url: &'static str,
}

pub static CONFIG: Config = Config {
    client_id: "client1",
    client_secret: "secret456",
    redirect_uri: "http://localhost:3000/callback",
    auth_server_url: "http://localhost:4000",
    resource_server_url: "http://localhost:5000",
};

#[derive(Deserialize, Debug)]
pub struct CallbackQueryParams {
    pub auth_code: String,
}

#[derive(Deserialize, Debug)]
pub struct TokenResponse {
    pub expires_in: i64,
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
    pub is_revoked: bool,
}
