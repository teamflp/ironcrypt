use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::info;

/// Represents the outcome of a cryptographic operation.
#[derive(Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
}

/// Represents the type of cryptographic operation performed.
#[derive(Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    GenerateKey,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Rekey,
}

/// A structured event for auditing cryptographic operations.
#[derive(Serialize, Debug)]
pub struct AuditEvent {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub operation: Operation,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recipient_key_versions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symmetric_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key_version: Option<String>,
}

impl AuditEvent {
    /// Creates a new audit event.
    pub fn new(operation: Operation) -> Self {
        Self {
            timestamp: Utc::now(),
            operation,
            outcome: Outcome::Success, // Default to success
            error_message: None,
            key_type: None,
            key_size: None,
            key_version: None,
            recipient_key_versions: Vec::new(),
            symmetric_algorithm: None,
            signature_algorithm: None,
            signer_key_version: None,
        }
    }

    /// Logs the event using the `tracing` crate.
    ///
    /// This serializes the entire event struct into a JSON object, which is then
    /// logged. This works well with `tracing_subscriber::fmt().json()`.
    pub fn log(&self) {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::Object(map)) => {
                info!(target: "audit", event = ?map);
            }
            _ => {
                // Fallback for safety, though it shouldn't happen with this struct.
                info!(target: "audit", "Failed to serialize audit event");
            }
        }
    }
}
