use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyConfig {
    pub description: String,
    pub key_hash: String,
    pub permissions: Vec<Permission>,
}
