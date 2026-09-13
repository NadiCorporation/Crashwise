pub mod builder;
pub mod compiler;
pub mod detector;
pub mod target_manager;

pub use builder::TargetBuilder;
pub use compiler::BuildOutput;
pub use detector::{detect_build_system, detect_single_file_target, BuildSystemType, DetectedBuildSystem};
pub use target_manager::{TargetManager, TargetSpec};
