use chrono::{DateTime, Duration, Utc};
use url::Url;

mod auth_middleware;
use auth_middleware::AuthMiddleware;

mod params;
use params::{LoginForm, LoginQueryParams, OauthTokenParams, TokenParams, TokenResponse};

use std::future::ready;

use actix_web::{
    error::{ErrorBadRequest, ErrorInternalServerError, ErrorUnauthorized},
    get,
    http::header::ContentType,
    post, web, HttpResponse,
};

use app_core::auth_utils::{is_valid_credentials, Credentials, IntrospectResponse, TokenStatus};
use app_core::jwt::{Claims, Jwt};
use app_core::storage::{AuthCode, Storage, Token};

#[get("/authorize")]
async fn login(query: web::Query<LoginQueryParams>) -> Result<HttpResponse, actix_web::Error> {
    let LoginQueryParams {
        client_id,
        redirect_uri,
        response_type,
        scope,
    } = query.into_inner();

    let client = Storage::get_client(&client_id).map_err(ErrorInternalServerError)?;

    match client {
        Some(cl) => Ok(HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(format!(
                "<h2>{} is requesting access to:</h2>
                <form method=\"post\" action=\"/authorize\">
                    <input type=\"hidden\" name=\"client_id\" value=\"{}\" />
                    <input type=\"hidden\" name=\"redirect_uri\" value=\"{}\" />
                    <input type=\"hidden\" name=\"response_type\" value=\"{}\" />
                    <input type=\"hidden\" name=\"scope\" value=\"{}\" />
                    <input type=\"text\" name=\"username\" placeholder=\"Username\" /><br>
                    <input type=\"password\" name=\"password\" placeholder=\"Password\" /><br>
                    <button type=\"submit\">Authorize</button>
            </form>",
                cl.name, client_id, redirect_uri, response_type, scope
            ))),
        None => Ok(HttpResponse::BadRequest().body("Invalid client")),
    }
}

#[post("/authorize")]
async fn login_post(form: web::Form<LoginForm>) -> Result<HttpResponse, actix_web::Error> {
    let form = form.into_inner();
    let creds = Credentials {
        client_id: form.client_id.clone(),
        client_secret: None,
    };
    let storage = Storage::default();
    let is_valid = is_valid_credentials(&creds, &storage).map_err(|e| ErrorBadRequest(e))?;
    if !is_valid {
        return Ok(HttpResponse::Unauthorized().body("Invalid credentials"));
    }

    let user = Storage::get_user_by_credentials(&form.username, &form.password);

    match user {
        Ok(_) => {
            let auth_code = String::from("123");
            let user_id = "user1".to_string();
            let now: DateTime<Utc> = Utc::now();
            let expires = (now + Duration::minutes(10)).timestamp();

            let auth_code_data = AuthCode {
                client_id: form.client_id,
                redirect_uri: form.redirect_uri.clone(),
                user_id,
                scope: form.scope,
                expires,
            };
            let _ = Storage::store_auth_code(&auth_code, auth_code_data);

            let mut redirect_url =
                Url::parse(&form.redirect_uri).map_err(|err| ErrorInternalServerError(err))?;

            redirect_url
                .query_pairs_mut()
                .append_pair("auth_code", &auth_code);

            Ok(HttpResponse::Found()
                .append_header(("Location", redirect_url.to_string()))
                .finish())
        }
        Err(err) => return Ok(HttpResponse::Unauthorized().body(err.to_string())),
    }
}

#[post("/token")]
async fn oauth_token(
    params: web::Json<OauthTokenParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let params = params.into_inner();

    if params.grant_type != "authorization_code" {
        return Ok(HttpResponse::BadRequest().body("Unsupported grant type"));
    }
    let storage = Storage::default();
    let is_valid = is_valid_credentials(
        &Credentials {
            client_id: params.client_id.clone(),
            client_secret: Some(params.client_secret),
        },
        &storage,
    )
    .map_err(|e| ErrorUnauthorized(e))?;
    if !is_valid {
        return Ok(HttpResponse::Unauthorized().body("Invalid credentials"));
    }

    let auth_code = match Storage::get_auth_code(&params.auth_code) {
        Ok(ac) => ac,
        Err(err) => return Ok(HttpResponse::Unauthorized().body(err.to_string())),
    };

    let now = Utc::now().timestamp();
    if auth_code.expires < now || auth_code.redirect_uri != params.redirect_uri {
        return Ok(HttpResponse::Unauthorized().body("Invalid grant"));
    }

    let now = Utc::now();
    let expires_in = 24 * 3600;
    let expires = (now + Duration::seconds(expires_in)).timestamp();
    let claims = Claims {
        sub: params.client_id.clone(),
        exp: expires,
        iat: now.timestamp(),
    };

    let access_token =
        Jwt::encode(&claims).map_err(|_| ErrorUnauthorized("Token creation failed"))?;

    let token_data = Token {
        client_id: auth_code.client_id.clone(),
        user_id: auth_code.user_id.clone(),
        scope: auth_code.scope.clone(),
        expires,
        is_revoked: false,
    };

    let _ = Storage::store_token(&access_token, token_data);
    // storage.auth_codes.remove(&params.auth_code); // revoke auth_code after getting token
    let response = TokenResponse {
        access_token,
        token_type: String::from("Bearer"),
        expires_in,
        scope: auth_code.scope.clone(),
        is_revoked: false,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/revoke")]
async fn revoke(params: web::Json<TokenParams>) -> Result<HttpResponse, actix_web::Error> {
    let result = Storage::revoke_token(&params.access_token);
    if result.is_ok() {
        Ok(HttpResponse::Ok().body("Revoked token"))
    } else {
        Ok(HttpResponse::BadRequest().body("Invalid token"))
    }
}

#[post("/introspect")]
async fn introspect(params: web::Json<TokenParams>) -> Result<HttpResponse, actix_web::Error> {
    if let Ok(Some(token)) = Storage::get_token(&params.access_token) {
        let mut response = IntrospectResponse {
            status: TokenStatus::Active,
            scope: token.scope.clone(),
            expires: token.expires,
        };

        let now = Utc::now().timestamp();
        if token.is_revoked {
            response.status = TokenStatus::Revoked;
        } else if token.expires < now {
            response.status = TokenStatus::Expired;
        }
        return Ok(HttpResponse::Ok().json(response));
    };

    Ok(HttpResponse::BadRequest().body("Invalid token"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_web::{App, HttpServer};

    let app_port = 4000;
    println!("Listening on port {}", app_port);

    let config = Jwt::from_env();
    let config = web::Data::new(config);

    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .service(login)
            .service(login_post)
            .service(oauth_token)
            .service(
                web::scope("")
                    .wrap(actix_web_httpauth::middleware::HttpAuthentication::bearer(
                        move |req, _| ready(AuthMiddleware::validate_token(req)),
                    ))
                    .service(introspect)
                    .service(revoke),
            )
    })
    .bind(("127.0.0.1", app_port))?
    .run()
    .await
}
