use std::path::PathBuf;

pub use crate::builder::TargetBuilder;

#[derive(Debug, Clone)]
pub struct BuildOutput {
    pub static_libs: Vec<PathBuf>,
    pub shared_libs: Vec<PathBuf>,
    pub include_dirs: Vec<PathBuf>,
    pub compile_commands_path: Option<PathBuf>,
}
