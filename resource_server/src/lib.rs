use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub enum TokenStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TokenResponse {
    pub expires: DateTime<Utc>,
    pub scope: String,
    pub status: TokenStatus,
}
