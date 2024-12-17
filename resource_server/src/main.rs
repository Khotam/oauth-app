use actix_web::{error::ErrorBadRequest, post, web, App, HttpRequest, HttpResponse, HttpServer};
use app_core::auth_utils::{IntrospectResponse, TokenStatus};
use app_core::sd_jwt;
use reqwest::header::AUTHORIZATION;

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

#[post("/resource")]
async fn resource(req: HttpRequest) -> Result<HttpResponse, actix_web::Error> {
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

    let sd_jwt = sd_jwt::issue_vc();

    return Ok(HttpResponse::Ok().json(web::Json(serde_json::json!({
        "ok": true,
        "sd_jwt": sd_jwt
    }))));
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_port = 5000;
    println!("Listening on port {}", app_port);

    HttpServer::new(|| App::new().service(resource))
        .bind(("127.0.0.1", app_port))?
        .run()
        .await
}
