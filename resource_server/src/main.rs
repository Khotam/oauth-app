use actix_web::error::ErrorInternalServerError;
use actix_web::get;
use actix_web::{error::ErrorBadRequest, post, web, App, HttpRequest, HttpResponse, HttpServer};
use app_core::auth_utils::{IntrospectResponse, TokenStatus};
use app_core::edcsa_key_generator::{
    encode_private_key_to_pem, generate_ecdsa_private_key, generate_ecdsa_public_key,
};
use app_core::sd_jwt;
use reqwest::header::AUTHORIZATION;
use serde_json::json;

#[derive(Debug)]
enum RequestError {
    NetworkErr(String),
    ParsingErr(String),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::NetworkErr(msg) => write!(f, "Network error: {}", msg),
            RequestError::ParsingErr(msg) => write!(f, "JSON parsing error: {}", msg),
        }
    }
}

async fn validate_token(token: &str) -> Result<bool, RequestError> {
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:4000/introspect")
        .json(&serde_json::json!({
          "access_token": token,
        }))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .map_err(|err| RequestError::NetworkErr(format!("/introspect - {}", err)))?;

    let token: IntrospectResponse = response
        .json()
        .await
        .map_err(|err| RequestError::ParsingErr(format!("/introspect - {}", err)))?;

    if token.status == TokenStatus::Active {
        return Ok(true);
    }

    return Ok(false);
}

#[get("/public-key")]
async fn public_key(config: web::Data<AppState>) -> Result<HttpResponse, actix_web::Error> {
    let public_key_pem = generate_ecdsa_public_key(config.private_key_bytes.clone());
    match public_key_pem {
        Err(err) => Ok(HttpResponse::InternalServerError()
            .body(format!("public key generation failed: {}", err))),
        Ok(pub_key_pem) => Ok(HttpResponse::Ok().json(json!({
            "public_key_pem": pub_key_pem,
        }))),
    }
}

#[post("/resource")]
async fn resource(
    req: HttpRequest,
    config: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let client = reqwest::Client::new();
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.replace("Bearer ", ""));

    if token.is_none() {
        return Ok(HttpResponse::Unauthorized().body("invalid token"));
    }

    let is_valid = validate_token(&token.unwrap())
        .await
        .map_err(|err| ErrorBadRequest(err))?;

    if !is_valid {
        return Ok(HttpResponse::Unauthorized().body("invalid token"));
    }

    let holder_server_url = "http://localhost:3000";
    let response = client
        .get(format!("{}/public-key", holder_server_url))
        .send()
        .await
        .map_err(|err| ErrorInternalServerError(err))?;
    // dbg!(&response);
    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|err| ErrorInternalServerError(err))?;

    let holder_public_key_jwk = json["public_key_jwk"].as_str().unwrap_or_default();
    // dbg!(&holder_public_key_jwk);
    let sd_jwt = sd_jwt::issue_vc(
        config.private_key_pem.clone(),
        holder_public_key_jwk.to_string(),
    )
    .map_err(|err| ErrorInternalServerError(err))?;

    return Ok(HttpResponse::Ok().json(web::Json(serde_json::json!({
        "ok": true,
        "sd_jwt": sd_jwt,
    }))));
}

#[derive(Clone, Debug)]
struct AppState {
    private_key_bytes: Vec<u8>,
    private_key_pem: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_port = 5000;
    println!("Listening on port {}", app_port);

    let private_key_bytes: Vec<u8> = generate_ecdsa_private_key().unwrap_or_else(|err| {
        println!("cannot generate private key: {}", err);
        panic!("app failed to generate issuer private key");
    });

    let private_key_pem = encode_private_key_to_pem(&private_key_bytes);

    let config = web::Data::new(AppState {
        private_key_bytes,
        private_key_pem,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .service(resource)
            .service(public_key)
    })
    .bind(("127.0.0.1", app_port))?
    .run()
    .await
}
