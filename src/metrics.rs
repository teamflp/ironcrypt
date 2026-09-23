use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Once;
use std::time::Instant;

use metrics::{counter, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

static INIT: Once = Once::new();

/// Initialise l’exporter Prometheus si activé via les variables d’environnement.
///
/// - `IRONCRYPT_METRICS_ENABLED=true` pour activer
/// - `IRONCRYPT_METRICS_PORT=9000` pour définir le port
/// - `IRONCRYPT_METRICS_BIND=127.0.0.1` (défaut) — ne pas exposer `/metrics` publiquement
pub fn init_metrics() {
    INIT.call_once(|| {
        let enabled = env::var("IRONCRYPT_METRICS_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if !enabled {
            return;
        }

        let port = env::var("IRONCRYPT_METRICS_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(9000);

        let bind = env::var("IRONCRYPT_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1".into());
        let ip: IpAddr = bind.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        if !ip.is_loopback() {
            if crate::payment::PaymentSecurityProfile::is_enabled() {
                eprintln!(
                    "ERROR: Payment profile refuses non-loopback metrics bind ({ip}); \
                     set IRONCRYPT_METRICS_BIND=127.0.0.1"
                );
                return;
            }
            eprintln!(
                "WARNING: Prometheus metrics bound to non-loopback {ip} — \
                 restrict with network policy / sidecar; prefer 127.0.0.1"
            );
        }

        let addr = SocketAddr::new(ip, port);

        match PrometheusBuilder::new().with_http_listener(addr).install() {
            Ok(_) => eprintln!("Prometheus exporter listening on {addr}"),
            Err(e) => eprintln!("Failed to start Prometheus exporter: {e}"),
        }
    });
}

/// Démarre un timer pour mesurer la durée d’une commande.
pub fn metrics_start() -> Instant {
    Instant::now()
}

/// Enregistre les métriques à la fin de l’exécution d’une commande.
///
/// Labels are restricted to `command` + `status` only — never put secrets,
/// API keys, tenants, PANs, or request payloads in Prometheus labels.
pub fn metrics_finish(command: &str, payload_bytes: u64, start: Instant, success: bool) {
    let elapsed = start.elapsed().as_secs_f64();
    let status = if success { "ok" } else { "error" };

    debug_assert!(
        SAFE_METRIC_LABEL_KEYS.contains(&"command")
            && SAFE_METRIC_LABEL_KEYS.contains(&"status")
    );
    let labels = [("command", command.to_string()), ("status", status.to_string())];
    histogram!("command_duration_seconds", &labels).record(elapsed);
    histogram!("payload_size_bytes", &labels).record(payload_bytes as f64);
    counter!("commands_executed_total", &labels).increment(1);
}

/// Record a CryptoProvider wrap/unwrap/encrypt attempt (daemon / library callers).
///
/// Labels: `op` ∈ {wrap,unwrap,encrypt,decrypt}, `status` ∈ {ok,error},
/// `provider` = backend name (never a key id or secret).
pub fn provider_op_finish(provider: &str, op: &str, start: Instant, success: bool) {
    let elapsed = start.elapsed().as_secs_f64();
    let status = if success { "ok" } else { "error" };
    let labels = [
        ("provider", sanitize_provider_label(provider)),
        ("op", op.to_string()),
        ("status", status.to_string()),
    ];
    histogram!("crypto_provider_duration_seconds", &labels).record(elapsed);
    counter!("crypto_provider_ops_total", &labels).increment(1);
}

fn sanitize_provider_label(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "unknown".into()
    } else {
        cleaned
    }
}

/// Label keys permitted on IronCrypt Prometheus time series.
pub const SAFE_METRIC_LABEL_KEYS: &[&str] = &["command", "status", "provider", "op"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_labels_are_allowlisted() {
        for key in SAFE_METRIC_LABEL_KEYS {
            assert!(
                !matches!(
                    *key,
                    "api_key"
                        | "authorization"
                        | "password"
                        | "tenant"
                        | "pan"
                        | "secret"
                        | "token"
                        | "key_id"
                ),
                "forbidden metric label: {key}"
            );
        }
    }

    #[test]
    fn sanitize_provider() {
        assert_eq!(sanitize_provider_label("aws-kms"), "aws-kms");
        assert_eq!(sanitize_provider_label("evil/../x"), "evil____x");
    }
}
