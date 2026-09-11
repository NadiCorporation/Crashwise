use thiserror::Error;

#[derive(Error, Debug)]
pub enum CrashwiseError {
    #[error("Target build error: {0}")]
    BuildError(String),

    #[error("AST parsing error: {0}")]
    AstError(String),

    #[error("Harness synthesis error: {0}")]
    HarnessError(String),

    #[error("Fuzzing engine error: {0}")]
    EngineError(String),

    #[error("Crash triage error: {0}")]
    TriageError(String),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CrashwiseError>;
