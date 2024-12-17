use jsonwebtoken::{DecodingKey, EncodingKey};
use sd_jwt_rs::{
    ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat,
    SDJWTVerifier,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    first_name: String,
    last_name: String,
    age: i8,
}

fn get_user_claims() -> Value {
    json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        }
    )
}

pub fn issue_vc() -> String {
    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";

    let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
    let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();

    let mut issuer = SDJWTIssuer::new(issuer_key, None);
    let sd_jwt = issuer
        .issue_sd_jwt(
            get_user_claims(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap();

    sd_jwt
}

pub fn create_vp(sd_jwt: String) -> String {
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let claims_to_disclose = get_user_claims().as_object().unwrap().clone();
    let presentation = holder
        .create_presentation(claims_to_disclose, None, None, None, None)
        .unwrap();

    presentation
}

pub fn verify_vp(presentation: String) -> serde_json::Value {
    const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";
    let verified_claims = SDJWTVerifier::new(
        presentation,
        Box::new(|_, _| {
            let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
            DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
        }),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .unwrap()
    .verified_claims;

    verified_claims
}
