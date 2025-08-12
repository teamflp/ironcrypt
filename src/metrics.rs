use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Once;
use std::time::Instant;

use metrics::histogram; // ✅ import correct
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_macros::increment_counter;


static INIT: Once = Once::new();

/// Initialise l’exporter Prometheus si activé via les variables d’environnement.
///
/// - `IRONCRYPT_METRICS_ENABLED=true` pour activer
/// - `IRONCRYPT_METRICS_PORT=9000` pour définir le port
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

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);

        match PrometheusBuilder::new().with_http_listener(addr).install() {
            Ok(_) => println!("✅ Prometheus exporter actif sur {}", addr),
            Err(e) => eprintln!("❌ Échec du démarrage de l’exporter Prometheus : {}", e),
        }
    });
}

/// Démarre un timer pour mesurer la durée d’une commande.
pub fn metrics_start() -> Instant {
    Instant::now()
}

/// Enregistre les métriques à la fin de l’exécution d’une commande.
pub fn metrics_finish(command: &str, payload_bytes: u64, start: Instant, success: bool) {
    let elapsed = start.elapsed().as_secs_f64();
    let status = if success { "ok" } else { "error" };

    // ✅ On passe les labels sous forme de slice de tuples (compatible metrics 0.24.2)
    let labels = [("command", command), ("status", status)];

    histogram!("command_duration_seconds", elapsed, &labels);
    histogram!("payload_size_bytes", payload_bytes as f64, &labels);
    increment_counter!("commands_executed_total", &labels);
}
