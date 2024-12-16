use actix_web::{
    dev::ServiceRequest, error::ErrorUnauthorized, http::header::AUTHORIZATION, Error,
};
use jsonwebtoken::{decode, DecodingKey, Validation};

pub struct AuthMiddleware;

impl AuthMiddleware {
    pub fn validate_token(
        req: ServiceRequest,
        secret: &str,
    ) -> Result<ServiceRequest, (Error, ServiceRequest)> {
        println!("middleware");
        dbg!(req.headers().get(AUTHORIZATION));
        let auth_header = if let Some(header) = req.headers().get(AUTHORIZATION) {
            if let Ok(auth_str) = header.to_str() {
                auth_str
            } else {
                return Err((ErrorUnauthorized("Invalid authorization header"), req));
            }
        } else {
            return Err((ErrorUnauthorized("Missing authorization header"), req));
        };

        if !auth_header.starts_with("Bearer ") {
            return Err((ErrorUnauthorized("Invalid authorization scheme"), req));
        }

        let token = &auth_header[7..];

        match decode::<super::Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        ) {
            Ok(_token_data) => Ok(req),
            Err(_) => Err((ErrorUnauthorized("Invalid token"), req)),
        }
    }
}
