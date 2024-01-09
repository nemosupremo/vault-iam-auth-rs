use std::collections::HashMap;

use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct TokenResponse<T> {
    pub data: Option<T>,
    pub auth: Option<AuthInfo>,
    pub lease_id: String,
    pub lease_duration: u32,
    pub renewable: bool,
    pub request_id: String,
    pub warnings: Option<Vec<String>>,
    pub wrap_info: Option<WrapInfo>,
}

#[derive(Deserialize, Debug)]
pub struct AuthInfo {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub token_policies: Vec<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub lease_duration: u64,
    pub renewable: bool,
    pub entity_id: String,
    pub token_type: String,
    pub orphan: bool,
}

#[derive(Deserialize, Debug)]
pub struct WrapInfo {
    pub token: String,
    pub accessor: String,
    pub ttl: u64,
    pub creation_time: String,
    pub creation_path: String,
}
