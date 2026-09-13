use crate::patch_synth::PatchCandidate;
use crashwise_core::error::{CrashwiseError, Result};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

/// RAII Guard that automatically rolls back applied patch modifications unless explicitly committed.
#[derive(Debug)]
pub struct PatchGuard {
    target_file: PathBuf,
    backup_path: PathBuf,
    active: bool,
}

impl PatchGuard {
    pub fn new(target_file: PathBuf, backup_path: PathBuf) -> Self {
        Self {
            target_file,
            backup_path,
            active: true,
        }
    }

    pub fn target_file(&self) -> &Path {
        &self.target_file
    }

    pub fn backup_path(&self) -> &Path {
        &self.backup_path
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Transactionally roll back the file to its original pre-patch contents.
    pub fn rollback(&mut self) -> Result<()> {
        if self.active {
            if self.backup_path.exists() {
                fs::copy(&self.backup_path, &self.target_file).map_err(|e| {
                    CrashwiseError::TriageError(format!(
                        "Failed to restore backup {} to {}: {e}",
                        self.backup_path.display(),
                        self.target_file.display()
                    ))
                })?;
                let _ = fs::remove_file(&self.backup_path);
            }
            self.active = false;
        }
        Ok(())
    }

    /// Commit the patch permanently and remove the backup file.
    pub fn commit(&mut self) {
        if self.active {
            if self.backup_path.exists() {
                let _ = fs::remove_file(&self.backup_path);
            }
            self.active = false;
        }
    }
}

impl Drop for PatchGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = self.rollback();
        }
    }
}

/// Atomic patch application engine with transactional backup and rollback.
pub struct PatchApplier;

impl PatchApplier {
    /// Apply unified diff content to an in-memory string.
    /// Returns modified string on success or unmodified string / error on corrupted hunk.
    pub fn apply_diff_to_content(original_content: &str, unified_diff: &str) -> std::result::Result<String, String> {
        if unified_diff.trim().is_empty() {
            return Ok(original_content.to_string());
        }

        let diff_lines: Vec<&str> = unified_diff.lines().collect();
        if !diff_lines.iter().any(|line| line.starts_with("@@")) {
            return Err("Invalid diff: no valid hunks found".to_string());
        }

        let mut lines: Vec<String> = original_content.lines().map(|s| s.to_string()).collect();

        let hunk_re = Regex::new(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@").unwrap();
        let mut idx = 0;

        while idx < diff_lines.len() {
            let line = diff_lines[idx];
            if line.starts_with("@@") {
                if let Some(caps) = hunk_re.captures(line) {
                    let old_start: usize = match caps[1].parse() {
                        Ok(s) => s,
                        Err(_) => {
                            idx += 1;
                            continue;
                        }
                    };

                    let mut current_pos = if old_start > 0 { old_start - 1 } else { 0 };
                    if current_pos > lines.len() {
                        current_pos = lines.len();
                    }

                    idx += 1;
                    while idx < diff_lines.len()
                        && !diff_lines[idx].starts_with("@@")
                        && !diff_lines[idx].starts_with("---")
                    {
                        let hunk_line = diff_lines[idx];
                        if let Some(added) = hunk_line.strip_prefix('+') {
                            if current_pos <= lines.len() {
                                lines.insert(current_pos, added.to_string());
                                current_pos += 1;
                            }
                        } else if hunk_line.starts_with('-') {
                            if current_pos < lines.len() {
                                lines.remove(current_pos);
                            }
                        } else if hunk_line.starts_with(' ') {
                            current_pos += 1;
                        }
                        idx += 1;
                    }
                    continue;
                }
            }
            idx += 1;
        }

        let mut result = lines.join("\n");
        if original_content.ends_with('\n') {
            result.push('\n');
        }
        Ok(result)
    }

    /// Apply unified diff to a target file, generating a `.orig.bak` backup.
    pub fn apply_patch_file_with_backup(target_file: &Path, unified_diff: &str) -> Result<PathBuf> {
        let content = fs::read_to_string(target_file).map_err(|e| {
            CrashwiseError::TriageError(format!(
                "Failed to read target file {}: {e}",
                target_file.display()
            ))
        })?;

        let patched = Self::apply_diff_to_content(&content, unified_diff)
            .map_err(CrashwiseError::TriageError)?;

        let mut backup_os = target_file.as_os_str().to_os_string();
        backup_os.push(".orig.bak");
        let backup_path = PathBuf::from(backup_os);

        fs::write(&backup_path, &content).map_err(|e| {
            CrashwiseError::TriageError(format!(
                "Failed to write backup {}: {e}",
                backup_path.display()
            ))
        })?;

        if let Err(e) = fs::write(target_file, patched) {
            let _ = fs::remove_file(&backup_path);
            return Err(CrashwiseError::TriageError(format!(
                "Failed to write patched file {}: {e}",
                target_file.display()
            )));
        }

        Ok(backup_path)
    }

    /// Roll back a patched file using its backup copy.
    pub fn rollback_patch(target_file: &Path, backup_path: &Path) -> Result<()> {
        if backup_path.exists() {
            fs::copy(backup_path, target_file).map_err(|e| {
                CrashwiseError::TriageError(format!(
                    "Failed to rollback {} from {}: {e}",
                    target_file.display(),
                    backup_path.display()
                ))
            })?;
            fs::remove_file(backup_path).map_err(|e| {
                CrashwiseError::TriageError(format!("Failed to clean backup: {e}"))
            })?;
        }
        Ok(())
    }

    /// Apply diff to target file and return an active `PatchGuard`.
    pub fn apply(target_file: &Path, unified_diff: &str) -> Result<PatchGuard> {
        let backup_path = Self::apply_patch_file_with_backup(target_file, unified_diff)?;
        Ok(PatchGuard::new(target_file.to_path_buf(), backup_path))
    }

    /// Apply a `PatchCandidate` within a target source directory.
    pub fn apply_patch(target_dir: &Path, patch: &PatchCandidate) -> Result<PatchGuard> {
        let target_file = Self::resolve_target_file(target_dir, &patch.file_path)?;
        Self::apply(&target_file, &patch.unified_diff)
    }

    fn resolve_target_file(target_dir: &Path, file_path_str: &str) -> Result<PathBuf> {
        let path = Path::new(file_path_str);
        if path.is_absolute() {
            return Err(CrashwiseError::TriageError(
                "Path traversal escape attempted: absolute path not allowed".into(),
            ));
        }

        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(CrashwiseError::TriageError(
                "Path traversal escape attempted: parent directory navigation not allowed".into(),
            ));
        }

        let canonical_target = target_dir.canonicalize().map_err(|e| {
            CrashwiseError::TriageError(format!(
                "Failed to canonicalize target_dir {}: {e}",
                target_dir.display()
            ))
        })?;

        // Direct relative match
        let candidate1 = target_dir.join(file_path_str);
        if candidate1.exists() {
            if let Ok(canonical_candidate) = candidate1.canonicalize() {
                if canonical_candidate.starts_with(&canonical_target) {
                    return Ok(canonical_candidate);
                } else {
                    return Err(CrashwiseError::TriageError("Path traversal escape attempted".into()));
                }
            }
        }

        // Strip "a/" or "b/" git diff prefix
        let stripped = file_path_str
            .strip_prefix("a/")
            .or_else(|| file_path_str.strip_prefix("b/"))
            .unwrap_or(file_path_str);

        let stripped_path = Path::new(stripped);
        if stripped_path.is_absolute()
            || stripped_path.components().any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(CrashwiseError::TriageError("Path traversal escape attempted".into()));
        }

        let candidate2 = target_dir.join(stripped);
        if candidate2.exists() {
            if let Ok(canonical_candidate) = candidate2.canonicalize() {
                if canonical_candidate.starts_with(&canonical_target) {
                    return Ok(canonical_candidate);
                } else {
                    return Err(CrashwiseError::TriageError("Path traversal escape attempted".into()));
                }
            }
        }

        // Search by filename in target_dir
        if let Some(file_name) = stripped_path.file_name() {
            for entry in walkdir(target_dir) {
                if entry.file_name() == Some(file_name) {
                    if let Ok(canonical_entry) = entry.canonicalize() {
                        if canonical_entry.starts_with(&canonical_target) {
                            return Ok(canonical_entry);
                        }
                    }
                }
            }
        }

        Err(CrashwiseError::TriageError(format!(
            "Target file not found for patch: {} in {}",
            file_path_str,
            target_dir.display()
        )))
    }
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                files.extend(walkdir(&path));
            }
        }
    }
    files
}
