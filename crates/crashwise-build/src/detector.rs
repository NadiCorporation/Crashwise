use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildSystemType {
    CMake,
    Meson,
    Bazel,
    Cargo,
    Make,
    Autotools,
    Custom,
}

#[derive(Debug, Clone)]
pub struct DetectedBuildSystem {
    pub build_type: BuildSystemType,
    pub root_dir: PathBuf,
    pub build_file: PathBuf,
}

pub fn detect_build_system(dir: &Path) -> Option<DetectedBuildSystem> {
    if dir.join("CMakeLists.txt").exists() {
        return Some(DetectedBuildSystem {
            build_type: BuildSystemType::CMake,
            root_dir: dir.to_path_buf(),
            build_file: dir.join("CMakeLists.txt"),
        });
    }

    if dir.join("meson.build").exists() {
        return Some(DetectedBuildSystem {
            build_type: BuildSystemType::Meson,
            root_dir: dir.to_path_buf(),
            build_file: dir.join("meson.build"),
        });
    }

    if dir.join("WORKSPACE").exists() || dir.join("MODULE.bazel").exists() || dir.join("BUILD").exists() {
        return Some(DetectedBuildSystem {
            build_type: BuildSystemType::Bazel,
            root_dir: dir.to_path_buf(),
            build_file: dir.join("BUILD"),
        });
    }

    if dir.join("Cargo.toml").exists() {
        return Some(DetectedBuildSystem {
            build_type: BuildSystemType::Cargo,
            root_dir: dir.to_path_buf(),
            build_file: dir.join("Cargo.toml"),
        });
    }

    if dir.join("Makefile").exists() || dir.join("makefile").exists() || dir.join("GNUmakefile").exists() {
        return Some(DetectedBuildSystem {
            build_type: BuildSystemType::Make,
            root_dir: dir.to_path_buf(),
            build_file: dir.join("Makefile"),
        });
    }

    if dir.join("configure.ac").exists() || dir.join("configure.in").exists() || dir.join("configure").exists() {
        return Some(DetectedBuildSystem {
            build_type: BuildSystemType::Autotools,
            root_dir: dir.to_path_buf(),
            build_file: dir.join("configure"),
        });
    }

    None
}
