use actix_web::{post, web, App, HttpResponse, HttpServer};
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
    let presentation = params.presentation.clone();

    let verified_claims = sd_jwt::verify_vp(presentation.clone());

    Ok(HttpResponse::Ok().json(json!({
        "presentation": presentation,
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
