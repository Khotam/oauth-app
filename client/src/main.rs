use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use client::{CallbackQueryParams, TokenResponse, CONFIG};
use reqwest::header::AUTHORIZATION;

use serde_json;

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
        Ok(res) => Ok(HttpResponse::Ok().body(
            res.text()
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?,
        )),
        Err(e) => {
            println!("Error: {e}");
            Ok(HttpResponse::Unauthorized().body(e.to_string()))
        }
    }
}

// #[post("/echo")]
// async fn echo(req_body: String) -> impl Responder {
//     HttpResponse::Ok().body(req_body)
// }

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_port = 3000;
    println!("Listening on port {}", &app_port);

    HttpServer::new(|| App::new().service(index).service(callback))
        .bind(("127.0.0.1", app_port))?
        .run()
        .await
}
