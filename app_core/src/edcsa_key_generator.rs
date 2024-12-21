use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::{
    rand,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use yasna::models::ObjectIdentifier;

pub fn generate_ecdsa_private_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;

    Ok(pkcs8_bytes.as_ref().to_vec())
}

pub fn encode_private_key_to_pem(private_key_bytes: &[u8]) -> String {
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        STANDARD.encode(private_key_bytes)
    );

    pem
}

pub fn generate_ecdsa_public_key(
    private_key_bytes: Vec<u8>,
) -> Result<String, Box<dyn std::error::Error>> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        private_key_bytes.as_ref(),
        &ring::rand::SystemRandom::new(),
    )?;

    let public_key = key_pair.public_key();

    //  Create ASN.1 DER encoding for the public key
    let public_key_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                // OID for ECDSA with P-256
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1])); // ecPublicKey
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
                // prime256v1/secp256r1
            });
            writer
                .next()
                .write_bitvec_bytes(&public_key.as_ref(), public_key.as_ref().len() * 8);
        })
    });

    let public_key_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        STANDARD.encode(&public_key_der)
    );

    Ok(public_key_pem)
}
