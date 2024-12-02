use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use resource_server::{TokenResponse, TokenStatus};

async fn validate_token(token: &String) -> bool {
    let client = reqwest::Client::new();
    let response = match client
        .post("http://localhost:4000/introspect")
        .json(&serde_json::json!({
          "access_token": token,
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            println!("Request failed: {}", e);
            return false;
        }
    };

    let token: TokenResponse = match response.json().await {
        Ok(t) => t,
        Err(e) => {
            println!("Failed to parse response: {}", e);
            return false;
        }
    };
    if token.status == TokenStatus::Active {
        return true;
    }

    return false;
}

#[post("/resource")]
async fn resource(req: HttpRequest) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.replace("Bearer ", ""));

    match token {
        Some(t) => {
            let is_valid = validate_token(&t).await;
            if is_valid {
                return HttpResponse::Ok().json(web::Json(serde_json::json!({
                    "ok": true,
                })));
            }

            return HttpResponse::Unauthorized().body("invalid token");
        }
        None => HttpResponse::Unauthorized().body("invalid token"),
    }
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
