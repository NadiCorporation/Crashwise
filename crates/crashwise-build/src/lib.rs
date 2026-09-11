pub mod compiler;
pub mod detector;

pub use compiler::{BuildOutput, TargetBuilder};
pub use detector::{detect_build_system, BuildSystemType, DetectedBuildSystem};
