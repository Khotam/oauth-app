use auth_server::{
    is_valid_credentials, Credentials, IntrospectResponse, LoginForm, LoginQueryParams,
    OauthTokenParams, TokenParams, TokenResponse, TokenStatus,
};
use chrono::{DateTime, Duration, Utc};
use url::Url;
mod storage;
use storage::{AuthCode, Client, Profile, Storage, Token, User};

use actix_web::{
    error::{ErrorBadRequest, ErrorInternalServerError},
    get,
    http::header::ContentType,
    post, web, App, HttpResponse, HttpServer,
};

#[get("/authorize")]
async fn login(query: web::Query<LoginQueryParams>) -> Result<HttpResponse, actix_web::Error> {
    let LoginQueryParams {
        client_id,
        redirect_uri,
        response_type,
        scope,
    } = query.into_inner();

    let storage = Storage::get().map_err(|e| ErrorInternalServerError(e))?;
    let client = storage.clients.get(&client_id);

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
    let is_valid = is_valid_credentials(&creds).map_err(|e| ErrorBadRequest(e))?;
    if !is_valid {
        return Ok(HttpResponse::Unauthorized().body("Invalid credentials"));
    }

    let mut storage = Storage::get().map_err(|e| ErrorInternalServerError(e))?;
    let user = storage
        .users
        .values()
        .find(|user| user.username == form.username && user.password == form.password);

    match user {
        Some(_) => {
            let auth_code = String::from("123");
            let user_id = "user1".to_string();
            let now: DateTime<Utc> = Utc::now();
            let expires = now + Duration::minutes(10);

            let auth_code_data = AuthCode {
                client_id: form.client_id,
                redirect_uri: form.redirect_uri.clone(),
                user_id,
                scope: form.scope,
                expires,
            };
            storage.auth_codes.insert(auth_code.clone(), auth_code_data);

            let mut redirect_url =
                Url::parse(&form.redirect_uri).map_err(|err| ErrorInternalServerError(err))?;

            redirect_url
                .query_pairs_mut()
                .append_pair("auth_code", &auth_code);

            Ok(HttpResponse::Found()
                .append_header(("Location", redirect_url.to_string()))
                .finish())
        }
        None => return Ok(HttpResponse::Unauthorized().body("Invalid credentials")),
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

    let mut storage = Storage::get().map_err(|e| ErrorInternalServerError(e))?;

    let is_valid = is_valid_credentials(&Credentials {
        client_id: params.client_id,
        client_secret: Some(params.client_secret),
    })
    .map_err(|e| ErrorBadRequest(e))?;
    if !is_valid {
        return Ok(HttpResponse::Unauthorized().body("Invalid credentials"));
    }

    let auth_code = match storage.auth_codes.get(&params.auth_code).cloned() {
        Some(ac) => ac, // Clone the data we need
        None => return Ok(HttpResponse::BadRequest().json("Invalid auth code")),
    };

    let now = Utc::now();
    if auth_code.expires < now || auth_code.redirect_uri != params.redirect_uri {
        return Ok(HttpResponse::Unauthorized().body("Invalid grant"));
    }

    let expires = now + Duration::minutes(10);
    let access_token = String::from("token");
    let token_data = Token {
        client_id: auth_code.client_id.clone(),
        user_id: auth_code.user_id.clone(),
        scope: auth_code.scope.clone(),
        expires,
        is_revoked: false,
    };

    storage.tokens.insert(access_token.clone(), token_data);
    // storage.auth_codes.remove(&params.auth_code);
    let response = TokenResponse {
        access_token,
        token_type: String::from("Bearer"),
        expires_in: 3600,
        scope: auth_code.scope.clone(),
        is_revoked: false,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/revoke")]
async fn revoke(params: web::Json<TokenParams>) -> Result<HttpResponse, actix_web::Error> {
    let mut storage = Storage::get().map_err(|e| ErrorInternalServerError(e))?;

    if let Some(token) = storage.tokens.get_mut(&params.access_token) {
        token.is_revoked = true;
        return Ok(HttpResponse::Ok().body("Revoked"));
    }
    Ok(HttpResponse::BadRequest().body("Invalid token"))
}

#[post("/introspect")]
async fn introspect(params: web::Json<TokenParams>) -> Result<HttpResponse, actix_web::Error> {
    let storage = Storage::get().map_err(|e| ErrorInternalServerError(e))?;

    if let Some(token) = storage.tokens.get(&params.access_token) {
        let mut response = IntrospectResponse {
            status: TokenStatus::Active,
            scope: token.scope.clone(),
            expires: token.expires,
        };

        let now = Utc::now();

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
async fn main() -> Result<(), std::io::Error> {
    let app_port = 4000;
    println!("Listening on port {}", app_port);

    let storage = Storage::get();
    match storage {
        Ok(mut strg) => {
            strg.clients.insert(
                String::from("client1"),
                Client {
                    client_secret: String::from("client1_secret"),
                    redirect_uris: vec![String::from("http://localhost:3000/callback")],
                    name: String::from("Client App"),
                    allowed_scopes: vec![String::from("email"), String::from("photos")],
                },
            );

            strg.users.insert(
                String::from("user1"),
                User {
                    username: String::from("username"),
                    password: String::from("password"),
                    profile: Profile {
                        name: String::from("Khotam"),
                        email: String::from("test@gmail.com"),
                    },
                },
            );
            ()
        }
        _ => (),
    }

    HttpServer::new(|| {
        App::new()
            .service(login)
            .service(login_post)
            .service(oauth_token)
            .service(revoke)
            .service(introspect)
    })
    .bind(("127.0.0.1", app_port))?
    .run()
    .await
}
