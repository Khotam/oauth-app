use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::{
    rand,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::json;
use uuid::Uuid;

pub fn generate_ed25519_private_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;

    Ok(pkcs8_bytes.as_ref().to_vec())
}

pub fn encode_ed25519_key_to_pem(private_key_bytes: &Vec<u8>) -> String {
    // Create PEM format for private key
    let private_key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        STANDARD.encode(private_key_bytes)
    );

    private_key_pem
}

pub fn generate_ed25519_public_key(
    private_key_bytes: Vec<u8>,
) -> Result<String, Box<dyn std::error::Error>> {
    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_bytes)?;
    let public_key = key_pair.public_key();
    let jwk = json!({
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kid": Uuid::new_v4().to_string(),
        "kty": "OKP",
        "x": STANDARD.encode(public_key.as_ref())
    })
    .to_string();

    Ok(jwk)
}
