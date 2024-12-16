use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone, Debug)]
pub struct JwtConfig {
    pub secret: String,
}

impl JwtConfig {
    pub fn from_env() -> Self {
        dotenv().ok();

        Self {
            secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
        }
    }
}
