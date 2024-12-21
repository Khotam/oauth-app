use dotenv::dotenv;
use jsonwebtoken::{decode, encode, errors::Error, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone, Debug)]
pub struct Jwt {
    pub secret: String,
}

impl Jwt {
    pub fn from_env() -> Self {
        dotenv().ok();

        Self {
            secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
        }
    }

    pub fn encode(claims: &Claims) -> Result<String, Error> {
        let jwt_secret_key = Jwt::from_env();

        let jwt_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret_key.secret.as_bytes()),
        );

        jwt_token
    }

    pub fn decode(token: &str) -> Result<jsonwebtoken::TokenData<Claims>, Error> {
        let jwt_secret_key = Jwt::from_env();

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret_key.secret.as_bytes()),
            &Validation::default(),
        )
    }
}
