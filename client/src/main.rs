use actix_web::error::ErrorInternalServerError;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use app_core::client_utils::{CallbackQueryParams, TokenResponse, CONFIG};
use app_core::ed25519_key_generator::generate_ed25519_public_key;
use app_core::{ed25519_key_generator, sd_jwt};
use reqwest::header::AUTHORIZATION;

use serde_json::{self, json};

#[get("/")]
async fn index() -> impl Responder {
    let auth_url = format!(
        "{}/authorize?\
        client_id={}&\
        redirect_uri={}&\
        response_type=code&\
        scope=profile email photos",
        CONFIG.auth_server_url, CONFIG.client_id, CONFIG.redirect_uri
    );

    HttpResponse::Ok().body(format!("<a href=\"{}\">Authorize with OAuth</a>", auth_url))
}

#[get("/callback")]
async fn callback(
    query: web::Query<CallbackQueryParams>,
    config: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let auth_code = &query.auth_code;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/token", CONFIG.auth_server_url))
        .json(&serde_json::json!({
          "grant_type": "authorization_code",
          "auth_code": auth_code,
          "redirect_uri": CONFIG.redirect_uri,
          "client_id": CONFIG.client_id,
          "client_secret": CONFIG.client_secret,
        }))
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let token_data: TokenResponse = response
        .json()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let resp = client
        .post(format!("{}/resource", CONFIG.resource_server_url))
        .header(AUTHORIZATION, format!("Bearer {}", token_data.access_token))
        .json(&serde_json::json!({
          "grant_type": "authorization_code",
          "auth_code": auth_code,
          "redirect_uri": CONFIG.redirect_uri,
          "client_id": CONFIG.client_id,
          "client_secret": CONFIG.client_secret,
        }))
        .send()
        .await;

    match resp {
        Ok(res) => {
            let json: serde_json::Value = res
                .json()
                .await
                .map_err(|err| ErrorInternalServerError(err))?;
            let sd_jwt = json["sd_jwt"].as_str().unwrap_or_default();
            let presentation = sd_jwt::create_vp(&config.private_key_pem, sd_jwt.to_string())
                .map_err(|err| ErrorInternalServerError(err))?;

            let client = reqwest::Client::new();
            let verifier_response = client
                .post(format!("{}/presentation", CONFIG.verifier_server_url))
                // .header(AUTHORIZATION, format!("Bearer {}", token_data.access_token))
                .json(&serde_json::json!({
                  "presentation": presentation,
                }))
                .send()
                .await;

            if verifier_response.is_err() {
                return Ok(
                    HttpResponse::Unauthorized().body(verifier_response.err().unwrap().to_string())
                );
            }

            return Ok(HttpResponse::Unauthorized().body(
                verifier_response
                    .ok()
                    .unwrap()
                    .text()
                    .await
                    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?,
            ));
        }
        Err(e) => {
            println!("Error: {e}");
            Ok(HttpResponse::Unauthorized().body(e.to_string()))
        }
    }
}

#[get("/public-key")]
async fn public_key(config: web::Data<AppState>) -> Result<HttpResponse, actix_web::Error> {
    let public_key_jwk = generate_ed25519_public_key(config.private_key_bytes.clone());
    match public_key_jwk {
        Err(err) => Ok(HttpResponse::InternalServerError()
            .body(format!("public key generation failed: {}", err))),
        Ok(pub_key_jwk) => Ok(HttpResponse::Ok().json(json!({
            "public_key_jwk": pub_key_jwk,
        }))),
    }
}

#[derive(Debug, Clone)]
struct AppState {
    private_key_bytes: Vec<u8>,
    private_key_pem: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_port = 3000;
    println!("Listening on port {}", &app_port);

    let private_key_bytes =
        ed25519_key_generator::generate_ed25519_private_key().unwrap_or_else(|err| {
            println!("Failed to create private key: {}", err);
            panic!("Failed to create private key");
        });

    let private_key_pem = ed25519_key_generator::encode_ed25519_key_to_pem(&private_key_bytes);

    let config = web::Data::new(AppState {
        private_key_bytes,
        private_key_pem,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .service(index)
            .service(callback)
            .service(public_key)
    })
    .bind(("127.0.0.1", app_port))?
    .run()
    .await
}
