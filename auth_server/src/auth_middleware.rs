use actix_web::{
    dev::ServiceRequest, error::ErrorUnauthorized, http::header::AUTHORIZATION, Error,
};
use app_core::jwt::Jwt;

// #[derive(Debug)]
// pub struct TokenValidationError {
//     pub error: actix_web::error::Error,
//     pub request: ServiceRequest,
// }

pub struct AuthMiddleware;

impl AuthMiddleware {
    pub fn validate_token(req: ServiceRequest) -> Result<ServiceRequest, (Error, ServiceRequest)> {
        // ) -> Result<ServiceRequest, TokenValidationError> {
        let auth_header = if let Some(header) = req.headers().get(AUTHORIZATION) {
            if let Ok(auth_str) = header.to_str() {
                auth_str
            } else {
                return Err((ErrorUnauthorized("Invalid authorization header"), req));
                // return Err(TokenValidationError {
                //     request: req,
                //     error: ErrorUnauthorized("Invalid auth header"),
                // });
            }
        } else {
            return Err((ErrorUnauthorized("Missing auth header"), req));
            // return Err(TokenValidationError {
            //     request: req,
            //     error: ErrorUnauthorized("Missing auth header"),
            // });
        };

        if !auth_header.starts_with("Bearer ") {
            return Err((ErrorUnauthorized("Invalid auth schema"), req));

            // return Err(TokenValidationError {
            //     request: req,
            //     error: ErrorUnauthorized("Invalid auth schema"),
            // });
        }

        let token = &auth_header[7..];

        match Jwt::decode(token) {
            Ok(_token_data) => Ok(req),
            Err(_) => Err((ErrorUnauthorized("Invalid token"), req)),
            // Err(_) => Err(TokenValidationError {
            //     request: req,
            //     error: ErrorUnauthorized("Invalid token"),
            // }),
        }
    }
}
