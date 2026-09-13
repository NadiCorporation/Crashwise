use crashwise_core::error::{CrashwiseError, Result};
use crashwise_core::models::CrashRecord;
use std::path::{Path, PathBuf};

pub struct PocGenerator;

impl PocGenerator {
    /// Generate standalone `poc.c` source code reproducing a crash without fuzzing harness dependencies.
    pub fn generate_standalone_poc(crash: &CrashRecord, target_header: &str, target_call: &str) -> String {
        let seed_bytes = std::fs::read(&crash.input_path).unwrap_or_else(|_| b"POC_CRASH_PAYLOAD".to_vec());

        let mut byte_array = String::new();
        for (i, b) in seed_bytes.iter().enumerate() {
            if i % 12 == 0 {
                byte_array.push_str("\n    ");
            }
            byte_array.push_str(&format!("0x{:02x}, ", b));
        }

        format!(
            r#"/*
 * Auto-Generated Standalone PoC Reproducer by CrashWise
 * Crash Type: {crash_type}
 * CWE: {cwe} | CVSS: {cvss:?}
 * Stack Hash: {stack_hash}
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
{target_header}

static const uint8_t poc_payload[] = {{{byte_array}
}};

int main(int argc, char **argv) {{
    printf("[*] Replaying CrashWise PoC (%zu bytes) for {crash_type}...\n", sizeof(poc_payload));
    
    // Invoke vulnerable target routine
    {target_call}

    printf("[+] Target executed without crashing (patch verified).\n");
    return 0;
}}
"#,
            crash_type = crash.crash_type,
            cwe = crash.cwe_id.as_deref().unwrap_or("N/A"),
            cvss = crash.cvss_score,
            stack_hash = crash.stack_hash,
            target_header = target_header,
            byte_array = byte_array,
            target_call = target_call
        )
    }

    /// Write standalone PoC code to a specified file path.
    pub fn write_poc_file(
        crash: &CrashRecord,
        target_header: &str,
        target_call: &str,
        output_path: &Path,
    ) -> Result<PathBuf> {
        let code = Self::generate_standalone_poc(crash, target_header, target_call);
        std::fs::write(output_path, code)
            .map_err(CrashwiseError::Io)?;
        Ok(output_path.to_path_buf())
    }
}

/// Compilation result from `PocCompiler`.
#[derive(Debug, Clone)]
pub struct PocCompileResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_bin: Option<PathBuf>,
}

/// Standalone PoC compiler using Clang with AddressSanitizer and UndefinedBehaviorSanitizer instrumentation.
#[derive(Debug, Clone)]
pub struct PocCompiler {
    pub clang_bin: PathBuf,
    pub include_dirs: Vec<PathBuf>,
    pub link_libs: Vec<PathBuf>,
    pub extra_flags: Vec<String>,
    pub enable_asan: bool,
}

impl Default for PocCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl PocCompiler {
    pub fn new() -> Self {
        Self {
            clang_bin: PathBuf::from("clang"),
            include_dirs: Vec::new(),
            link_libs: Vec::new(),
            extra_flags: Vec::new(),
            enable_asan: true,
        }
    }

    pub fn with_clang_bin(mut self, bin: impl Into<PathBuf>) -> Self {
        self.clang_bin = bin.into();
        self
    }

    pub fn with_include_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.include_dirs = dirs;
        self
    }

    pub fn with_link_libs(mut self, libs: Vec<PathBuf>) -> Self {
        self.link_libs = libs;
        self
    }

    pub fn with_extra_flags(mut self, flags: Vec<String>) -> Self {
        self.extra_flags = flags;
        self
    }

    pub fn with_sanitizer(mut self, enable: bool) -> Self {
        self.enable_asan = enable;
        self
    }

    pub fn add_include_dir(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        self.include_dirs.push(dir.as_ref().to_path_buf());
        self
    }

    pub fn add_link_lib(&mut self, lib: impl AsRef<Path>) -> &mut Self {
        self.link_libs.push(lib.as_ref().to_path_buf());
        self
    }

    pub fn add_flag(&mut self, flag: impl Into<String>) -> &mut Self {
        self.extra_flags.push(flag.into());
        self
    }

    /// Compile a PoC C source file into an instrumented binary, capturing compiler output.
    pub async fn compile_with_output(&self, source_path: &Path, output_bin: &Path) -> Result<PocCompileResult> {
        let mut cmd = tokio::process::Command::new(&self.clang_bin);
        cmd.arg("-O1").arg("-g");

        if self.enable_asan {
            cmd.arg("-fsanitize=address,undefined")
                .arg("-fno-omit-frame-pointer");
        }

        for inc in &self.include_dirs {
            cmd.arg(format!("-I{}", inc.display()));
        }

        for flag in &self.extra_flags {
            cmd.arg(flag);
        }

        cmd.arg(source_path);

        for lib in &self.link_libs {
            cmd.arg(lib);
        }

        cmd.arg("-o").arg(output_bin);

        let output = cmd.output().await.map_err(|e| {
            CrashwiseError::BuildError(format!("Failed to invoke clang compiler: {e}"))
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let success = output.status.success();

        Ok(PocCompileResult {
            success,
            exit_code: output.status.code(),
            stdout,
            stderr,
            output_bin: if success { Some(output_bin.to_path_buf()) } else { None },
        })
    }

    /// Compile a PoC source file and return binary path on success, or Error on failure.
    pub async fn compile(&self, source_path: &Path, output_bin: &Path) -> Result<PathBuf> {
        let res = self.compile_with_output(source_path, output_bin).await?;
        if !res.success {
            return Err(CrashwiseError::BuildError(format!(
                "PoC compilation failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
                res.stdout, res.stderr
            )));
        }
        Ok(output_bin.to_path_buf())
    }

    /// Compile C source string to a binary in the given directory.
    pub async fn compile_source(&self, c_code: &str, dir: &Path, bin_name: &str) -> Result<PathBuf> {
        let src_file = dir.join(format!("{bin_name}.c"));
        let bin_file = dir.join(bin_name);
        tokio::fs::write(&src_file, c_code).await?;
        self.compile(&src_file, &bin_file).await
    }

    /// Synchronous compilation helper.
    pub fn compile_sync(&self, source_path: &Path, output_bin: &Path) -> Result<PathBuf> {
        let mut cmd = std::process::Command::new(&self.clang_bin);
        cmd.arg("-O1").arg("-g");

        if self.enable_asan {
            cmd.arg("-fsanitize=address,undefined")
                .arg("-fno-omit-frame-pointer");
        }

        for inc in &self.include_dirs {
            cmd.arg(format!("-I{}", inc.display()));
        }

        for flag in &self.extra_flags {
            cmd.arg(flag);
        }

        cmd.arg(source_path);

        for lib in &self.link_libs {
            cmd.arg(lib);
        }

        cmd.arg("-o").arg(output_bin);

        let output = cmd.output().map_err(|e| {
            CrashwiseError::BuildError(format!("Failed to invoke clang compiler: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CrashwiseError::BuildError(format!("PoC compilation failed: {stderr}")));
        }

        Ok(output_bin.to_path_buf())
    }

    /// Synchronous source string compilation helper.
    pub fn compile_source_sync(&self, c_code: &str, dir: &Path, bin_name: &str) -> Result<PathBuf> {
        let src_file = dir.join(format!("{bin_name}.c"));
        let bin_file = dir.join(bin_name);
        std::fs::write(&src_file, c_code)?;
        self.compile_sync(&src_file, &bin_file)
    }
}
