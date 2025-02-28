use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::{web, App, HttpResponse, HttpServer, Responder, http::header, HttpRequest};
use common_macros::hash_set;
use dotenv::dotenv;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use actix_web::cookie::Key;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};

/// Application state holding the cached JWKS and Auth0 configuration.
#[derive(Clone)]
struct AppState {
    jwks: Value,
    auth0_domain: String,
    client_id: String,
    client_secret: String,
}

/// Structure for JSON responses.
#[derive(Serialize)]
struct GreetingResponse {
    message: String,
}

/// Structure for token claims (customize as needed).
#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    iat: usize,
    // add more fields if needed
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
}

/// Validates the JWT using the cached JWKS from AppState.
async fn validate_jwt(token: &str, state: &AppState) -> Result<Claims, actix_web::Error> {
    let auth0_domain = &state.auth0_domain;
    let client_id = &state.client_id;

    // Use the cached JWKS.
    let jwks = &state.jwks;
    let keys = jwks.get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Unable to get jwks keys"))?;

    // Decode header to get the kid.
    let header = decode_header(token)
        .map_err(|e| actix_web::error::ErrorUnauthorized(e))?;
    let kid = header.kid.ok_or_else(|| actix_web::error::ErrorUnauthorized("Token missing kid"))?;

    // Find the JWK that matches the kid.
    let jwk = keys.iter().find(|k| {
        k.get("kid")
         .and_then(|v| v.as_str())
         .map(|s| s == kid)
         .unwrap_or(false)
    }).ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid token: no matching kid"))?;

    let n = jwk.get("n")
        .and_then(|v| v.as_str())
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid token: no n value"))?;
    let e = jwk.get("e")
        .and_then(|v| v.as_str())
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid token: no e value"))?;

    let decoding_key = DecodingKey::from_rsa_components(n, e)
        .map_err(|err| actix_web::error::ErrorInternalServerError(err))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.iss = Some(hash_set!(format!("https://{}/", auth0_domain)));

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| actix_web::error::ErrorUnauthorized(e))?;

    Ok(token_data.claims)
}

/// Protected homepage – requires a valid session.
async fn index(session: Session, state: web::Data<AppState>) -> impl Responder {
    if let Some(token) = session.get::<String>("id_token").unwrap_or_default() {
        // Validate JWT to ensure the session token is still valid.
        if let Err(e) = validate_jwt(&token, &state).await {
            return HttpResponse::Unauthorized().body(format!("Invalid session token: {}", e));
        }
        HttpResponse::Ok()
            .content_type("text/html")
            .body(format!(r#"
                <html>
                    <head><title>Welcome</title></head>
                    <body>
                        <h1>Welcome!</h1>
                        <p>You are successfully logged in.</p>
                        
                        <p>Authenticated CURL example:</p>
                        <p style="font-family: monospace">curl -X GET http://localhost:8000/api/greetings -H "Authorization: Bearer {}"</p>
                        
                        <p>Invalid Token CURL example:</p>
                        <p style="font-family: monospace">curl -X GET http://localhost:8000/api/greetings -H "Authorization: Bearer someToken"</p>
                        
                        <p>Unauthorized CURL example:</p>
                        <p style="font-family: monospace">curl -X GET http://localhost:8000/api/greetings</p>
                        
                        <form action="/logout" method="get">
                            <button type="submit">Logout</button>
                        </form>
                    </body>
                </html>
            "#, token))
    } else {
        HttpResponse::Found()
            .append_header((header::LOCATION, "/login"))
            .finish()
    }
}

/// Initiates the Auth0 login/signup flow.
async fn login(state: web::Data<AppState>) -> impl Responder {
    let auth0_domain = &state.auth0_domain;
    let client_id = &state.client_id;
    let redirect_uri = "http://0.0.0.0:8000/callback";
    let authorize_url = format!(
        "https://{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email",
        auth0_domain, client_id, redirect_uri
    );

    HttpResponse::Found()
        .append_header((header::LOCATION, authorize_url))
        .finish()
}

/// Handles the Auth0 callback and stores session data.
async fn callback(
    query: web::Query<CallbackQuery>,
    session: Session,
    state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let auth0_domain = &state.auth0_domain;
    let client_id = &state.client_id;
    let client_secret = &state.client_secret;
    let redirect_uri = "http://0.0.0.0:8000/callback";

    let token_url = format!("https://{}/oauth/token", auth0_domain);
    let client = reqwest::Client::new();
    let params = serde_json::json!({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": query.code,
        "redirect_uri": redirect_uri
    });

    let res = client
        .post(&token_url)
        .json(&params)
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let token_resp: TokenResponse = res
        .json()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    session.insert("id_token", token_resp.id_token)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Found()
        .append_header((header::LOCATION, "/"))
        .finish())
}

/// Clears the session and logs out the user.
async fn logout(session: Session, state: web::Data<AppState>) -> impl Responder {
    session.purge();
    let auth0_domain = &state.auth0_domain;
    let client_id = &state.client_id;
    let return_to = "http://0.0.0.0:8000";
    let logout_url = format!(
        "https://{}/v2/logout?client_id={}&returnTo={}",
        auth0_domain, client_id, return_to
    );

    HttpResponse::Found()
        .append_header((header::LOCATION, logout_url))
        .finish()
}

/// Protected API endpoint returning a JSON greeting.
/// Supports both session cookie and bearer token authentication.
async fn api_greetings(req: HttpRequest, session: Session, state: web::Data<AppState>) -> impl Responder {
    if let Some(token) = session.get::<String>("id_token").unwrap_or(None) {
        if let Err(e) = validate_jwt(&token, &state).await {
            return HttpResponse::Unauthorized().body(format!("Invalid session token: {}", e));
        }
        let response = GreetingResponse { message: "Hello!".to_string() };
        return HttpResponse::Ok().json(response);
    }

    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = auth_str.trim_start_matches("Bearer ").trim();
                if !token.is_empty() {
                    if let Err(e) = validate_jwt(token, &state).await {
                        return HttpResponse::Unauthorized().body(format!("Unauthorized: {}", e));
                    }
                    let response = GreetingResponse { message: "Hello!".to_string() };
                    return HttpResponse::Ok().json(response);
                }
            }
        }
    }

    HttpResponse::Unauthorized().body("Unauthorized")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let key = Key::generate();

    // Load configuration from environment variables.
    let auth0_domain = env::var("AUTH0_DOMAIN").expect("AUTH0_DOMAIN must be set");
    let client_id = env::var("AUTH0_CLIENT_ID").expect("AUTH0_CLIENT_ID must be set");
    let client_secret = env::var("AUTH0_CLIENT_SECRET").expect("AUTH0_CLIENT_SECRET must be set");

    // Pre-fetch the JWKS from Auth0.
    let jwks_url = format!("https://{}/.well-known/jwks.json", auth0_domain);
    let jwks: Value = reqwest::get(&jwks_url)
        .await
        .expect("Failed to fetch JWKS")
        .json()
        .await
        .expect("Failed to parse JWKS");

    let state = AppState {
        jwks,
        auth0_domain,
        client_id,
        client_secret,
    };

    let state_data = web::Data::new(state);

    println!("Starting server at http://0.0.0.0:8000");

    HttpServer::new(move || {
        App::new()
            .app_data(state_data.clone())
            .wrap(SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
                .cookie_secure(false) // Set to true if using HTTPS.
                .build())
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login))
            .route("/callback", web::get().to(callback))
            .route("/logout", web::get().to(logout))
            .route("/api/greetings", web::get().to(api_greetings))
    })
    .bind("0.0.0.0:8000")?
    .run()
    .await
}
