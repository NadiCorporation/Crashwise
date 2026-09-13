use crate::compiler::BuildOutput;
use crate::detector::{detect_build_system, detect_single_file_target, BuildSystemType};
use crashwise_core::error::{CrashwiseError, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::info;

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

    pub fn with_sanitizers(mut self, sanitizers: Vec<String>) -> Self {
        self.sanitizers = sanitizers;
        self
    }

    pub async fn build_target(&self, target_dir: &Path, build_type: BuildSystemType) -> Result<BuildOutput> {
        match build_type {
            BuildSystemType::CMake => self.build_cmake(target_dir).await,
            BuildSystemType::Meson => self.build_meson(target_dir).await,
            BuildSystemType::Autotools => self.build_autotools(target_dir).await,
            BuildSystemType::Make => self.build_make(target_dir).await,
            _ => self.build_cmake(target_dir).await,
        }
    }

    pub async fn build_auto(&self, target_dir: &Path) -> Result<BuildOutput> {
        if let Some(detected) = detect_build_system(target_dir) {
            self.build_target(target_dir, detected.build_type).await
        } else if let Some(single_file) = detect_single_file_target(target_dir) {
            let include_dirs = vec![target_dir.to_path_buf()];
            self.build_single_file(&single_file, &include_dirs).await
        } else {
            Err(CrashwiseError::BuildError(format!(
                "No supported build system or single-file C target detected in {}",
                target_dir.display()
            )))
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

    pub async fn build_autotools(&self, target_dir: &Path) -> Result<BuildOutput> {
        let sanitizer_flags = format!("-fsanitize={} -fno-omit-frame-pointer -g -O1 -fsanitize=fuzzer-no-link", self.sanitizers.join(","));

        info!("Configuring Autotools target with instrumentation at {}", target_dir.display());

        let configure_script = target_dir.join("configure");
        if configure_script.exists() {
            let conf_status = Command::new("sh")
                .arg("./configure")
                .current_dir(target_dir)
                .env("CC", "clang")
                .env("CXX", "clang++")
                .env("CFLAGS", &sanitizer_flags)
                .env("CXXFLAGS", &sanitizer_flags)
                .status()
                .await
                .map_err(|e| CrashwiseError::BuildError(format!("Failed to invoke ./configure: {e}")))?;

            if !conf_status.success() {
                return Err(CrashwiseError::BuildError("Autotools ./configure step failed".to_string()));
            }
        }

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
            return Err(CrashwiseError::BuildError("Make execution failed in Autotools build".to_string()));
        }

        self.collect_libraries(target_dir, target_dir).await
    }

    pub async fn build_single_file(&self, source_file: &Path, include_dirs: &[PathBuf]) -> Result<BuildOutput> {
        let stem = source_file.file_stem().and_then(|s| s.to_str()).unwrap_or("target");
        let target_dir = source_file.parent().unwrap_or_else(|| Path::new("."));
        let build_dir = target_dir.join("build-crashwise");
        tokio::fs::create_dir_all(&build_dir).await?;

        let obj_file = build_dir.join(format!("{stem}.o"));
        let lib_file = build_dir.join(format!("lib{stem}.a"));

        let sanitizer_flags = format!("-fsanitize={} -fno-omit-frame-pointer -g -O1 -fsanitize=fuzzer-no-link", self.sanitizers.join(","));

        let mut cmd = Command::new("clang");
        cmd.arg("-c")
            .args(sanitizer_flags.split_whitespace())
            .arg("-fPIC")
            .arg(source_file)
            .arg("-o")
            .arg(&obj_file);

        for inc in include_dirs {
            cmd.arg(format!("-I{}", inc.display()));
        }
        cmd.arg(format!("-I{}", target_dir.display()));

        let output = cmd.output().await
            .map_err(|e| CrashwiseError::BuildError(format!("Failed to invoke clang: {e}")))?;
        if !output.status.success() {
            return Err(CrashwiseError::BuildError(format!(
                "Compilation of {} failed:\n{}",
                source_file.display(),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let ar_output = Command::new("ar")
            .args(["rcs"])
            .arg(&lib_file)
            .arg(&obj_file)
            .output()
            .await
            .map_err(|e| CrashwiseError::BuildError(format!("Failed to invoke ar: {e}")))?;
        if !ar_output.status.success() {
            return Err(CrashwiseError::BuildError(format!(
                "Archiving of {} failed:\n{}",
                lib_file.display(),
                String::from_utf8_lossy(&ar_output.stderr)
            )));
        }

        let mut all_incs = Self::collect_include_dirs(target_dir, Some(&build_dir), None);
        for inc in include_dirs {
            if inc.exists() && inc.is_dir() && !all_incs.contains(inc) {
                all_incs.push(inc.clone());
            }
        }

        Ok(BuildOutput {
            static_libs: vec![lib_file],
            shared_libs: vec![],
            include_dirs: all_incs,
            compile_commands_path: None,
        })
    }

    pub async fn collect_libraries(&self, search_dir: &Path, target_dir: &Path) -> Result<BuildOutput> {
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

        let include_dirs = Self::collect_include_dirs(
            target_dir,
            Some(search_dir),
            compile_commands_path.as_deref(),
        );

        Ok(BuildOutput {
            static_libs,
            shared_libs,
            include_dirs,
            compile_commands_path,
        })
    }

    pub fn collect_include_dirs(
        target_dir: &Path,
        build_dir: Option<&Path>,
        compile_commands: Option<&Path>,
    ) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = Vec::new();

        let mut add_dir = |p: PathBuf| {
            if p.exists() && p.is_dir() && !dirs.contains(&p) {
                dirs.push(p);
            }
        };

        // 1. Base project directories
        add_dir(target_dir.to_path_buf());
        add_dir(target_dir.join("include"));
        add_dir(target_dir.join("src"));

        // 2. Build directory and generated headers
        if let Some(bdir) = build_dir {
            if bdir.exists() {
                add_dir(bdir.to_path_buf());
                add_dir(bdir.join("include"));

                for entry in walkdir::WalkDir::new(bdir).into_iter().filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.components().any(|c| {
                        let s = c.as_os_str();
                        s == "CMakeFiles" || s == ".git"
                    }) {
                        continue;
                    }
                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                        if matches!(ext, "h" | "hpp" | "hxx" | "inc") {
                            if let Some(parent) = path.parent() {
                                add_dir(parent.to_path_buf());
                            }
                        }
                    }
                }
            }
        }

        // 3. Scan source directory for header subdirectories
        for entry in walkdir::WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.components().any(|c| {
                let s = c.as_os_str();
                s == "CMakeFiles" || s == ".git" || s == "build-crashwise" || s == "build-meson-crashwise"
            }) {
                continue;
            }
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if matches!(ext, "h" | "hpp" | "hxx" | "inc") {
                    if let Some(parent) = path.parent() {
                        add_dir(parent.to_path_buf());
                    }
                }
            }
        }

        // 4. compile_commands.json parsing
        if let Some(cc_path) = compile_commands {
            if cc_path.exists() {
                for inc in Self::extract_compile_commands_includes(cc_path) {
                    add_dir(inc);
                }
            }
        }

        dirs
    }

    pub fn extract_compile_commands_includes(compile_commands_path: &Path) -> Vec<PathBuf> {
        let mut includes = Vec::new();
        let content = match std::fs::read_to_string(compile_commands_path) {
            Ok(c) => c,
            Err(_) => return includes,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&content) {
            Ok(p) => p,
            Err(_) => return includes,
        };

        if let Some(entries) = parsed.as_array() {
            for entry in entries {
                let working_dir = entry.get("directory")
                    .and_then(|d| d.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));

                let tokens: Vec<String> = if let Some(args) = entry.get("arguments").and_then(|a| a.as_array()) {
                    args.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
                } else if let Some(cmd) = entry.get("command").and_then(|c| c.as_str()) {
                    cmd.split_whitespace().map(|s| s.to_string()).collect()
                } else {
                    Vec::new()
                };

                let mut iter = tokens.iter();
                while let Some(tok) = iter.next() {
                    let mut path_str = None;
                    if tok == "-I" || tok == "-isystem" {
                        if let Some(next) = iter.next() {
                            path_str = Some(next.as_str());
                        }
                    } else if tok.starts_with("-I") && tok.len() > 2 {
                        path_str = Some(&tok[2..]);
                    } else if tok.starts_with("-isystem") && tok.len() > 8 {
                        path_str = Some(&tok[8..]);
                    }

                    if let Some(p_str) = path_str {
                        let path = PathBuf::from(p_str);
                        let resolved = if path.is_absolute() {
                            path
                        } else {
                            working_dir.join(path)
                        };
                        if resolved.exists() && resolved.is_dir() && !includes.contains(&resolved) {
                            includes.push(resolved);
                        }
                    }
                }
            }
        }

        includes
    }
}
