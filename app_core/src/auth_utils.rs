use crate::storage::{ClientStorage, StorageError};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Deserialize, Serialize, PartialEq)]
pub enum TokenStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Deserialize, Serialize)]
pub struct IntrospectResponse {
    pub expires: i64,
    pub scope: String,
    pub status: TokenStatus,
}

pub fn is_valid_credentials<S: ClientStorage>(
    creds: &Credentials,
    storage: &S,
) -> Result<bool, StorageError> {
    let client = storage.get_client(&creds.client_id).map_err(|err| err)?;
    if let Some(client) = client {
        if let Some(client_secret) = &creds.client_secret {
            Ok(client.client_secret == *client_secret)
        } else {
            Ok(true)
        }
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::storage;

    struct MockStorage {
        clients: HashMap<String, storage::Client>,
        should_error: bool,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                clients: HashMap::new(),
                should_error: false,
            }
        }

        fn with_client(mut self, id: &str, secret: &str) -> Self {
            self.clients.insert(
                id.to_string(),
                storage::Client {
                    client_secret: secret.to_string(),
                    redirect_uris: vec![],
                    name: "test".to_string(),
                    allowed_scopes: vec![],
                },
            );
            self
        }

        fn with_error(mut self) -> Self {
            self.should_error = true;
            self
        }
    }

    impl ClientStorage for MockStorage {
        fn get_client(&self, client_id: &str) -> Result<Option<storage::Client>, StorageError> {
            if self.should_error {
                return Err(StorageError::NotFound);
            }
            Ok(self.clients.get(client_id).cloned())
        }
    }

    fn make_credentials(id: &str, secret: Option<&str>) -> Credentials {
        Credentials {
            client_id: id.to_string(),
            client_secret: secret.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_valid_credentials_with_secret() {
        let storage = MockStorage::new().with_client("valid_id", "correct_secret");
        let creds = make_credentials("valid_id", Some("correct_secret"));
        let result = is_valid_credentials(&creds, &storage);

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_invalid_secret() {
        let storage = MockStorage::new().with_client("valid_id", "correct_secret");
        let creds = make_credentials("valid_id", Some("wrong_secret"));
        let result = is_valid_credentials(&creds, &storage);

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_no_secret_provided() {
        let storage = MockStorage::new().with_client("valid_id", "any_secret");
        let creds = make_credentials("valid_id", None);
        let result = is_valid_credentials(&creds, &storage);

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_client_not_found() {
        let storage = MockStorage::new().with_client("valid_id", "any_secret");
        let creds = make_credentials("invalid_id", Some("any_secret"));
        let result = is_valid_credentials(&creds, &storage);

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_storage_error() {
        let storage = MockStorage::new().with_error();
        let creds = make_credentials("error_id", Some("any_secret"));
        let result = is_valid_credentials(&creds, &storage);

        assert!(result.is_err());
        // assert_eq!(result.unwrap_err(), "Storage error");
    }
}
