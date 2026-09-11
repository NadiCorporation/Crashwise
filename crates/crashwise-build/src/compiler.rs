use crate::detector::BuildSystemType;
use crashwise_core::error::{CrashwiseError, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::info;

pub struct BuildOutput {
    pub static_libs: Vec<PathBuf>,
    pub shared_libs: Vec<PathBuf>,
    pub include_dirs: Vec<PathBuf>,
    pub compile_commands_path: Option<PathBuf>,
}

pub struct TargetBuilder {
    pub workdir: PathBuf,
    pub sanitizers: Vec<String>,
}

impl TargetBuilder {
    pub fn new(workdir: PathBuf) -> Self {
        Self {
            workdir,
            sanitizers: vec!["address".to_string(), "undefined".to_string()],
        }
    }

    pub async fn build_target(&self, target_dir: &Path, build_type: BuildSystemType) -> Result<BuildOutput> {
        match build_type {
            BuildSystemType::CMake => self.build_cmake(target_dir).await,
            BuildSystemType::Meson => self.build_meson(target_dir).await,
            BuildSystemType::Make | BuildSystemType::Autotools => self.build_make(target_dir).await,
            _ => self.build_cmake(target_dir).await,
        }
    }

    pub async fn build_cmake(&self, target_dir: &Path) -> Result<BuildOutput> {
        let build_dir = target_dir.join("build-crashwise");
        tokio::fs::create_dir_all(&build_dir).await?;

        let sanitizer_flags = format!("-fsanitize={} -fno-omit-frame-pointer -g", self.sanitizers.join(","));
        let cflags = format!("{} -O1 -fsanitize=fuzzer-no-link", sanitizer_flags);

        info!("Configuring CMake target with instrumentation at {}", target_dir.display());

        let configure_status = Command::new("cmake")
            .current_dir(&build_dir)
            .args([
                "..",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                "-DCMAKE_C_COMPILER=clang",
                "-DCMAKE_CXX_COMPILER=clang++",
                &format!("-DCMAKE_C_FLAGS={}", cflags),
                &format!("-DCMAKE_CXX_FLAGS={}", cflags),
                "-DBUILD_SHARED_LIBS=OFF",
            ])
            .status()
            .await
            .map_err(|e| CrashwiseError::BuildError(format!("Failed to invoke cmake configure: {e}")))?;

        if !configure_status.success() {
            return Err(CrashwiseError::BuildError("CMake configure step failed".to_string()));
        }

        let build_status = Command::new("cmake")
            .current_dir(&build_dir)
            .args(["--build", ".", "--parallel"])
            .status()
            .await
            .map_err(|e| CrashwiseError::BuildError(format!("Failed to invoke cmake build: {e}")))?;

        if !build_status.success() {
            return Err(CrashwiseError::BuildError("CMake build step failed".to_string()));
        }

        self.collect_libraries(&build_dir, target_dir).await
    }

    pub async fn build_meson(&self, target_dir: &Path) -> Result<BuildOutput> {
        let build_dir = target_dir.join("build-meson-crashwise");
        let sanitizer_flags = self.sanitizers.join(",");

        info!("Configuring Meson target with instrumentation at {}", target_dir.display());

        let setup_status = Command::new("meson")
            .current_dir(target_dir)
            .args([
                "setup",
                "build-meson-crashwise",
                &format!("-Db_sanitize={}", sanitizer_flags),
                "-Ddefault_library=static",
            ])
            .env("CC", "clang")
            .env("CXX", "clang++")
            .status()
            .await
            .map_err(|e| CrashwiseError::BuildError(format!("Failed to invoke meson setup: {e}")))?;

        if !setup_status.success() {
            return Err(CrashwiseError::BuildError("Meson setup failed".to_string()));
        }

        let compile_status = Command::new("meson")
            .current_dir(&build_dir)
            .args(["compile"])
            .status()
            .await
            .map_err(|e| CrashwiseError::BuildError(format!("Failed to invoke meson compile: {e}")))?;

        if !compile_status.success() {
            return Err(CrashwiseError::BuildError("Meson compile failed".to_string()));
        }

        self.collect_libraries(&build_dir, target_dir).await
    }

    pub async fn build_make(&self, target_dir: &Path) -> Result<BuildOutput> {
        let sanitizer_flags = format!("-fsanitize={} -fno-omit-frame-pointer -g -O1 -fsanitize=fuzzer-no-link", self.sanitizers.join(","));

        info!("Building Makefile target with instrumentation at {}", target_dir.display());

        let make_status = Command::new("make")
            .current_dir(target_dir)
            .args(["-j"])
            .env("CC", "clang")
            .env("CXX", "clang++")
            .env("CFLAGS", &sanitizer_flags)
            .env("CXXFLAGS", &sanitizer_flags)
            .status()
            .await
            .map_err(|e| CrashwiseError::BuildError(format!("Failed to invoke make: {e}")))?;

        if !make_status.success() {
            return Err(CrashwiseError::BuildError("Make execution failed".to_string()));
        }

        self.collect_libraries(target_dir, target_dir).await
    }

    async fn collect_libraries(&self, search_dir: &Path, target_dir: &Path) -> Result<BuildOutput> {
        let mut static_libs = Vec::new();
        let mut shared_libs = Vec::new();

        for entry in walkdir::WalkDir::new(search_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "a" {
                    static_libs.push(path.to_path_buf());
                } else if ext == "so" || ext == "dylib" {
                    shared_libs.push(path.to_path_buf());
                }
            }
        }

        let compile_commands = search_dir.join("compile_commands.json");
        let compile_commands_path = if compile_commands.exists() {
            Some(compile_commands)
        } else {
            None
        };

        Ok(BuildOutput {
            static_libs,
            shared_libs,
            include_dirs: vec![
                target_dir.to_path_buf(),
                target_dir.join("include"),
                target_dir.join("src"),
            ],
            compile_commands_path,
        })
    }
}
