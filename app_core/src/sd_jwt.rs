use std::error::Error;

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

fn get_sample_nonce() -> String {
    "1234567890".to_string()
}

fn get_sample_aud() -> String {
    "abc".to_string()
}

pub fn issue_vc(private_key_pem: String) -> Result<String, Box<dyn Error>> {
    const HOLDER_JWK_KEY_ED25519: &str = r#"{
                "alg": "EdDSA",
                "crv": "Ed25519",
                "kid": "52128f2e-900e-414e-81c3-0b5f86f0f7b3",
                "kty": "OKP",
                "x": "24QLWXJ18wtbg3k_MDGhGM17Xh39UftuxbwJZzRLzkA"
            }"#;

    let issuer_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes()).unwrap_or_else(|e| {
        println!("Error creating key: {}", e);
        panic!("Failed to create key");
    });

    let holder_key = serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap();

    let mut issuer = SDJWTIssuer::new(issuer_key, None);
    let sd_jwt = issuer
        .issue_sd_jwt(
            get_user_claims(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(holder_key),
            false,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap();
    Ok(sd_jwt)
}

pub fn create_vp(sd_jwt: String) -> String {
    const HOLDER_KEY_ED25519: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOeIDnHHMoPCUTiq206gR+FdCdNtc31SzF1nKX31hvhd\n-----END PRIVATE KEY-----";
    let private_holder_key = EncodingKey::from_ed_pem(HOLDER_KEY_ED25519.as_bytes()).unwrap();

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let claims_to_disclose = get_user_claims().as_object().unwrap().clone();
    let presentation = holder
        .create_presentation(
            claims_to_disclose,
            Some(get_sample_nonce()),
            Some(get_sample_aud()),
            Some(private_holder_key),
            Some("EdDSA".to_string()),
        )
        .unwrap();

    presentation
}

pub fn verify_vp(
    public_key_pem: String,
    presentation: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let verified_claims = SDJWTVerifier::new(
        presentation.to_string(),
        Box::new(move |_, _| {
            DecodingKey::from_ec_pem(public_key_pem.as_bytes()).unwrap_or_else(|err| {
                println!("decode error: {}", err);
                panic!("decode");
            })
        }),
        Some(get_sample_aud()),
        Some(get_sample_nonce()),
        SDJWTSerializationFormat::Compact,
    )
    .unwrap()
    .verified_claims;

    Ok(verified_claims)
}
