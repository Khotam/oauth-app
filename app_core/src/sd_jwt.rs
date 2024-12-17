use jsonwebtoken::EncodingKey;
use sd_jwt_rs::{
    ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    first_name: String,
    last_name: String,
    age: i8,
}

pub fn issue() -> String {
    let issuer_key = EncodingKey::from_secret("secret".as_bytes());
    let claims = json!(Claims {
        first_name: "Khotam".to_string(),
        last_name: "Bakhromov".to_string(),
        age: 24
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

    sd_jwt
}

pub fn create_presentation(sd_jwt: String) -> String {
    let mut claims_to_disclosure = Map::new();
    claims_to_disclosure.insert("first_name".to_string(), json!("Khotam"));

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let presentation = holder
        .create_presentation(claims_to_disclosure, None, None, None, None)
        .unwrap();

    presentation
}

// pub fn verify(presentation: String) -> serde_json::Value {
//     let verified_claims = SDJWTVerifier::new(
//         presentation,
//         cb_to_resolve_issuer_key,
//         None,
//         None,
//         SDJWTSerializationFormat::Compact,
//     )
//     .unwrap()
//     .verified_claims;

//     verified_claims
// }
