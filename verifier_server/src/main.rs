use actix_web::{error::ErrorInternalServerError, post, web, App, HttpResponse, HttpServer};
use app_core::sd_jwt;

use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
struct PresentationParams {
    presentation: String,
}

#[post("/presentation")]
async fn presentation(
    params: web::Json<PresentationParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let issuer_server_url = "http://localhost:5000";
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/public-key", issuer_server_url))
        .send()
        .await
        .map_err(|err| ErrorInternalServerError(err))?;
    // dbg!(&response);

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|err| ErrorInternalServerError(err))?;

    let issuer_public_key_pem = json["public_key_pem"].as_str().unwrap();
    // dbg!(&issuer_public_key_pem);
    let verified_claims =
        sd_jwt::verify_vp(issuer_public_key_pem.to_string(), &params.presentation)?;

    Ok(HttpResponse::Ok().json(json!({
        "presentation": params.presentation,
        "verified_claims": verified_claims
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_port = 6000;
    println!("Listening on port {}", app_port);

    HttpServer::new(|| App::new().service(presentation))
        .bind(("127.0.0.1", app_port))?
        .run()
        .await
}
