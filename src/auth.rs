use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Write,
    Read,
    Delete,
    Update,
    Full,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyConfig {
    pub description: String,
    pub key_hash: String,
    pub permissions: Vec<Permission>,
    #[serde(default)]
    pub allowed_services: Option<Vec<String>>,
}
