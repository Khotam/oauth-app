use jsonwebtoken::EncodingKey;
use sd_jwt_rs::{ClaimsForSelectiveDisclosureStrategy, SDJWTIssuer, SDJWTSerializationFormat};
use serde_json::json;

pub fn issue() -> String {
    let issuer_key = EncodingKey::from_secret("secret".as_bytes());
    let claims = json!({
        "first_name": "Khotam",
        "lastname": "Bakhromov",
        "age": 24
    });

    let mut issuer = SDJWTIssuer::new(issuer_key, Some("HS256".to_string()));
    let sd_jwt = issuer
        .issue_sd_jwt(
            claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap();

    dbg!(&sd_jwt);

    sd_jwt
}
