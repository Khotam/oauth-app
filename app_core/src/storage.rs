use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
    pub profile: Profile,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires: i64,
    pub is_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub scope: String,
    pub expires: i64,
}

#[derive(Clone, Debug)]
pub struct Client {
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub name: String,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Storage {
    clients: HashMap<String, Client>,
    auth_codes: HashMap<String, AuthCode>,
    tokens: HashMap<String, Token>,
    users: HashMap<String, User>,
}

static STORAGE: Lazy<Mutex<Storage>> = Lazy::new(|| {
    let mut storage = Storage::default();

    storage.clients.insert(
        String::from("client1"),
        Client {
            client_secret: String::from("secret456"),
            redirect_uris: vec![String::from("http://localhost:3000/callback")],
            name: String::from("Client App"),
            allowed_scopes: vec![String::from("email"), String::from("photos")],
        },
    );

    storage.users.insert(
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

    Mutex::new(storage)
});

impl Storage {
    pub fn get_client(client_id: &str) -> Result<Option<Client>, String> {
        let storage = STORAGE
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;
        Ok(storage.clients.get(client_id).cloned())
    }

    pub fn get_user_by_credentials(username: &str, password: &str) -> Result<Option<User>, String> {
        let storage = STORAGE
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;
        Ok(storage
            .users
            .values()
            .find(|user| user.username == username && user.password == password)
            .cloned())
    }

    pub fn store_auth_code(code: &str, auth_code: AuthCode) -> Result<(), String> {
        let mut storage = STORAGE
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;
        storage.auth_codes.insert(code.to_string(), auth_code);
        Ok(())
    }

    pub fn get_auth_code(code: &str) -> Result<AuthCode, String> {
        let storage = STORAGE
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;

        let auth_code = storage.auth_codes.get(code).cloned();

        match auth_code {
            Some(ac) => Ok(ac),
            None => Err("not found".to_string()),
        }
    }

    pub fn store_token(access_token: &str, token: Token) -> Result<(), String> {
        let mut storage = STORAGE
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;
        storage.tokens.insert(access_token.to_string(), token);
        Ok(())
    }

    pub fn get_token(access_token: &str) -> Result<Option<Token>, String> {
        let storage = STORAGE
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;
        Ok(storage.tokens.get(access_token).cloned())
    }

    pub fn revoke_token(access_token: &str) -> Result<bool, String> {
        let mut storage = STORAGE
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;
        if let Some(token) = storage.tokens.get_mut(access_token) {
            token.is_revoked = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn print_debug_state() -> Result<(), String> {
        let storage = STORAGE
            .lock()
            .map_err(|e| format!("Failed to acquire lock: {}", e))?;
        println!("Current storage state: {:#?}", storage);
        Ok(())
    }
}

pub trait ClientStorage {
    fn get_client(&self, client_id: &str) -> Result<Option<Client>, String>;
}

// Implement the trait for our actual Storage struct
impl ClientStorage for Storage {
    fn get_client(&self, client_id: &str) -> Result<Option<Client>, String> {
        Storage::get_client(client_id)
    }
}
