use crashwise_core::config::CrashwiseConfig;
use crashwise_core::db::Database;
use crashwise_core::models::TelemetrySnapshot;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: CrashwiseConfig,
    pub telemetry_tx: broadcast::Sender<TelemetrySnapshot>,
    pub logs_tx: broadcast::Sender<String>,
}

impl AppState {
    pub fn new(db: Database, config: CrashwiseConfig) -> Self {
        let (telemetry_tx, _) = broadcast::channel(100);
        let (logs_tx, _) = broadcast::channel(500);

        Self {
            db,
            config,
            telemetry_tx,
            logs_tx,
        }
    }
}
