#![allow(dead_code)]

use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

pub const SHM_BITMAP_SIZE: usize = 65536;

pub struct ProcessResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub struct TestClang;

impl TestClang {
    pub fn compile_c(
        source_path: &Path,
        output_bin: &Path,
        enable_asan: bool,
        extra_flags: &[&str],
    ) -> Result<ProcessResult, String> {
        let mut cmd = Command::new("clang");
        cmd.arg("-O1").arg("-g");

        if enable_asan {
            cmd.arg("-fsanitize=address,undefined")
                .arg("-fno-omit-frame-pointer");
        }

        for flag in extra_flags {
            cmd.arg(flag);
        }

        cmd.arg(source_path).arg("-o").arg(output_bin);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to execute clang: {e}"))?;

        Ok(ProcessResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    pub fn compile_source_string(
        c_code: &str,
        dir: &Path,
        bin_name: &str,
        enable_asan: bool,
    ) -> Result<PathBuf, String> {
        let src_file = dir.join(format!("{bin_name}.c"));
        let bin_file = dir.join(bin_name);
        fs::write(&src_file, c_code)
            .map_err(|e| format!("Failed to write source file: {e}"))?;

        let res = Self::compile_c(&src_file, &bin_file, enable_asan, &[])?;
        if !res.success {
            return Err(format!(
                "Clang compilation failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
                res.stdout, res.stderr
            ));
        }
        Ok(bin_file)
    }
}

pub fn run_test_binary(
    binary_path: &Path,
    args: &[&str],
    env_vars: &[(&str, &str)],
    _timeout_secs: u64,
) -> Result<ProcessResult, String> {
    let mut cmd = Command::new(binary_path);
    for arg in args {
        cmd.arg(arg);
    }
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    // Default ASan options to ensure deterministic error strings
    if env_vars.iter().all(|(k, _)| *k != "ASAN_OPTIONS") {
        cmd.env(
            "ASAN_OPTIONS",
            "detect_leaks=0:abort_on_error=1:symbolize=1:disable_coredump=1",
        );
    }

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run binary {}: {e}", binary_path.display()))?;

    Ok(ProcessResult {
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Simulated shared memory coverage bitmap for LibAFL runner testing
#[derive(Clone)]
pub struct ShmCoverageBitmap {
    pub buffer: Vec<u8>,
    pub prev_location: usize,
}

impl ShmCoverageBitmap {
    pub fn new() -> Self {
        Self {
            buffer: vec![0u8; SHM_BITMAP_SIZE],
            prev_location: 0,
        }
    }

    pub fn record_edge(&mut self, current_location: usize) {
        let edge_idx = (self.prev_location ^ (current_location >> 1)) % SHM_BITMAP_SIZE;
        self.buffer[edge_idx] = self.buffer[edge_idx].saturating_add(1);
        self.prev_location = current_location >> 1;
    }

    pub fn count_covered_edges(&self) -> usize {
        self.buffer.iter().filter(|&&b| b > 0).count()
    }

    pub fn reset(&mut self) {
        self.buffer.fill(0);
        self.prev_location = 0;
    }
}

/// System V AMD64 ABI Layout Calculator according to standard rules
pub struct SystemVLayoutCalculator;

pub struct FieldOffsetInfo {
    pub name: String,
    pub type_name: String,
    pub offset: usize,
    pub size: usize,
    pub align: usize,
}

pub struct ResolvedStructLayout {
    pub name: String,
    pub total_size: usize,
    pub alignment: usize,
    pub fields: Vec<FieldOffsetInfo>,
    pub field_offsets: HashMap<String, usize>,
}

impl SystemVLayoutCalculator {
    pub fn get_type_size_align(type_name: &str) -> (usize, usize) {
        let trimmed = type_name.trim();
        if trimmed.ends_with('*') {
            return (8, 8);
        }
        match trimmed {
            "char" | "int8_t" | "uint8_t" | "unsigned char" | "bool" | "_Bool" => (1, 1),
            "short" | "int16_t" | "uint16_t" | "unsigned short" => (2, 2),
            "int" | "int32_t" | "uint32_t" | "unsigned int" | "float" => (4, 4),
            "long" | "int64_t" | "uint64_t" | "unsigned long" | "long long" | "double"
            | "size_t" | "ssize_t" | "uintptr_t" | "intptr_t" => (8, 8),
            _ => (8, 8), // Default pointers or unknown records
        }
    }

    pub fn resolve_struct(
        name: &str,
        fields: &[(&str, &str)], // (name, type)
    ) -> ResolvedStructLayout {
        let mut current_offset = 0;
        let mut max_align = 1;
        let mut field_infos = Vec::new();
        let mut offset_map = HashMap::new();

        for &(fname, ftype) in fields {
            let (fsize, falign) = Self::get_type_size_align(ftype);
            if falign > max_align {
                max_align = falign;
            }

            // Align current offset to field alignment requirement
            let padding = (falign - (current_offset % falign)) % falign;
            current_offset += padding;

            field_infos.push(FieldOffsetInfo {
                name: fname.to_string(),
                type_name: ftype.to_string(),
                offset: current_offset,
                size: fsize,
                align: falign,
            });
            offset_map.insert(fname.to_string(), current_offset);
            current_offset += fsize;
        }

        // Align total struct size to max member alignment
        let tail_padding = (max_align - (current_offset % max_align)) % max_align;
        let total_size = current_offset + tail_padding;

        ResolvedStructLayout {
            name: name.to_string(),
            total_size,
            alignment: max_align,
            fields: field_infos,
            field_offsets: offset_map,
        }
    }

    pub fn resolve_union(
        name: &str,
        fields: &[(&str, &str)],
    ) -> ResolvedStructLayout {
        let mut max_size = 0;
        let mut max_align = 1;
        let mut field_infos = Vec::new();
        let mut offset_map = HashMap::new();

        for &(fname, ftype) in fields {
            let (fsize, falign) = Self::get_type_size_align(ftype);
            if fsize > max_size {
                max_size = fsize;
            }
            if falign > max_align {
                max_align = falign;
            }
            field_infos.push(FieldOffsetInfo {
                name: fname.to_string(),
                type_name: ftype.to_string(),
                offset: 0,
                size: fsize,
                align: falign,
            });
            offset_map.insert(fname.to_string(), 0);
        }

        // Union size is max member size padded to max alignment
        let tail_padding = (max_align - (max_size % max_align)) % max_align;
        let total_size = max_size + tail_padding;

        ResolvedStructLayout {
            name: name.to_string(),
            total_size,
            alignment: max_align,
            fields: field_infos,
            field_offsets: offset_map,
        }
    }
}

/// Unified Diff and Patch Helper
pub struct PatchManager;

impl PatchManager {
    pub fn apply_diff_to_content(original_content: &str, unified_diff: &str) -> Result<String, String> {
        let mut lines: Vec<String> = original_content.lines().map(|s| s.to_string()).collect();
        let diff_lines: Vec<&str> = unified_diff.lines().collect();

        // Simple unified diff hunk processor
        let hunk_re = regex::Regex::new(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@").unwrap();
        let mut idx = 0;
        while idx < diff_lines.len() {
            let line = diff_lines[idx];
            if line.starts_with("@@") {
                // Parse @@ -start,len +start,len @@
                if let Some(caps) = hunk_re.captures(line) {
                    let old_start: usize = caps[1].parse().map_err(|e| format!("Invalid hunk start: {e}"))?;
                    let mut current_pos = if old_start > 0 { old_start - 1 } else { 0 };

                    idx += 1;
                    while idx < diff_lines.len() && !diff_lines[idx].starts_with("@@") && !diff_lines[idx].starts_with("---") {
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

    pub fn apply_patch_file_with_backup(target_file: &Path, unified_diff: &str) -> Result<PathBuf, String> {
        let content = fs::read_to_string(target_file)
            .map_err(|e| format!("Failed to read target file {}: {e}", target_file.display()))?;

        // Create backup
        let backup_path = target_file.with_extension("orig.bak");
        fs::write(&backup_path, &content)
            .map_err(|e| format!("Failed to write backup {}: {e}", backup_path.display()))?;

        let patched = Self::apply_diff_to_content(&content, unified_diff)?;
        fs::write(target_file, patched)
            .map_err(|e| format!("Failed to write patched content: {e}"))?;

        Ok(backup_path)
    }

    pub fn rollback_patch(target_file: &Path, backup_path: &Path) -> Result<(), String> {
        if backup_path.exists() {
            fs::copy(backup_path, target_file)
                .map_err(|e| format!("Failed to restore backup: {e}"))?;
            fs::remove_file(backup_path)
                .map_err(|e| format!("Failed to clean backup: {e}"))?;
        }
        Ok(())
    }
}

/// SQLite Feedback Memory Test Fixture
pub struct TestFeedbackMemoryDb {
    pub conn: Connection,
}

#[derive(Debug, Clone)]
pub struct FeedbackRecord {
    pub id: Uuid,
    pub campaign_id: Option<Uuid>,
    pub target_name: String,
    pub feedback_type: String,
    pub compiler_diagnostic: Option<String>,
    pub error_category: Option<String>,
    pub original_code: Option<String>,
    pub resolved_code: Option<String>,
    pub coverage_tokens: Option<Vec<String>>,
    pub success_count: u32,
    pub failure_count: u32,
    pub score: f32,
}

impl TestFeedbackMemoryDb {
    pub fn new_in_memory() -> Self {
        let conn = Connection::open_in_memory().expect("Failed to open SQLite memory DB");
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS agent_feedback_memory (
                id TEXT PRIMARY KEY,
                campaign_id TEXT,
                target_name TEXT NOT NULL,
                feedback_type TEXT NOT NULL,
                compiler_diagnostic TEXT,
                error_category TEXT,
                original_code TEXT,
                resolved_code TEXT,
                coverage_tokens TEXT,
                success_count INTEGER NOT NULL DEFAULT 0,
                failure_count INTEGER NOT NULL DEFAULT 0,
                score REAL NOT NULL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_target ON agent_feedback_memory(target_name);
            CREATE INDEX IF NOT EXISTS idx_feedback_type ON agent_feedback_memory(feedback_type);
            "#,
        )
        .expect("Failed to init agent_feedback_memory schema");

        Self { conn }
    }

    pub fn insert_record(&self, record: &FeedbackRecord) -> Result<(), rusqlite::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let tokens_json = record
            .coverage_tokens
            .as_ref()
            .map(|t| serde_json::to_string(t).unwrap_or_default());

        self.conn.execute(
            r#"INSERT INTO agent_feedback_memory (
                id, campaign_id, target_name, feedback_type, compiler_diagnostic,
                error_category, original_code, resolved_code, coverage_tokens,
                success_count, failure_count, score, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"#,
            params![
                record.id.to_string(),
                record.campaign_id.map(|id| id.to_string()),
                record.target_name,
                record.feedback_type,
                record.compiler_diagnostic,
                record.error_category,
                record.original_code,
                record.resolved_code,
                tokens_json,
                record.success_count,
                record.failure_count,
                record.score,
                now,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn query_similar_fixes(&self, diagnostic_term: &str, limit: usize) -> Vec<FeedbackRecord> {
        let pattern = format!("%{}%", diagnostic_term);
        let mut stmt = self
            .conn
            .prepare(
                r#"SELECT id, campaign_id, target_name, feedback_type, compiler_diagnostic,
                          error_category, original_code, resolved_code, coverage_tokens,
                          success_count, failure_count, score
                   FROM agent_feedback_memory
                   WHERE feedback_type = 'resolved_fix' AND compiler_diagnostic LIKE ?1
                   ORDER BY score DESC LIMIT ?2"#,
            )
            .unwrap();

        let rows = stmt
            .query_map(params![pattern, limit as i64], |row| {
                let id_str: String = row.get(0)?;
                let cid_str: Option<String> = row.get(1)?;
                let tokens_json: Option<String> = row.get(8)?;
                let tokens: Option<Vec<String>> = tokens_json.and_then(|s| serde_json::from_str(&s).ok());

                Ok(FeedbackRecord {
                    id: Uuid::parse_str(&id_str).unwrap_or_default(),
                    campaign_id: cid_str.and_then(|s| Uuid::parse_str(&s).ok()),
                    target_name: row.get(2)?,
                    feedback_type: row.get(3)?,
                    compiler_diagnostic: row.get(4)?,
                    error_category: row.get(5)?,
                    original_code: row.get(6)?,
                    resolved_code: row.get(7)?,
                    coverage_tokens: tokens,
                    success_count: row.get(9)?,
                    failure_count: row.get(10)?,
                    score: row.get(11)?,
                })
            })
            .unwrap();

        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn query_exemplars(&self, target: &str, limit: usize) -> Vec<FeedbackRecord> {
        let mut stmt = self
            .conn
            .prepare(
                r#"SELECT id, campaign_id, target_name, feedback_type, compiler_diagnostic,
                          error_category, original_code, resolved_code, coverage_tokens,
                          success_count, failure_count, score
                   FROM agent_feedback_memory
                   WHERE target_name = ?1 AND feedback_type IN ('harness_exemplar', 'resolved_fix')
                   ORDER BY score DESC LIMIT ?2"#,
            )
            .unwrap();

        let rows = stmt
            .query_map(params![target, limit as i64], |row| {
                let id_str: String = row.get(0)?;
                let cid_str: Option<String> = row.get(1)?;
                let tokens_json: Option<String> = row.get(8)?;
                let tokens: Option<Vec<String>> = tokens_json.and_then(|s| serde_json::from_str(&s).ok());

                Ok(FeedbackRecord {
                    id: Uuid::parse_str(&id_str).unwrap_or_default(),
                    campaign_id: cid_str.and_then(|s| Uuid::parse_str(&s).ok()),
                    target_name: row.get(2)?,
                    feedback_type: row.get(3)?,
                    compiler_diagnostic: row.get(4)?,
                    error_category: row.get(5)?,
                    original_code: row.get(6)?,
                    resolved_code: row.get(7)?,
                    coverage_tokens: tokens,
                    success_count: row.get(9)?,
                    failure_count: row.get(10)?,
                    score: row.get(11)?,
                })
            })
            .unwrap();

        rows.filter_map(|r| r.ok()).collect()
    }
}

// ---------------------------------------------------------------------------
// Tree-sitter AST Opaque-Box Test Harness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ParameterInfo {
    pub name: String,
    pub type_name: String,
    pub is_pointer: bool,
    pub is_const: bool,
}

#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<ParameterInfo>,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub is_static: bool,
    pub is_exported: bool,
    pub has_body: bool,
}

#[derive(Debug, Clone)]
pub struct StructFieldInfo {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone)]
pub struct StructInfo {
    pub name: String,
    pub fields: Vec<StructFieldInfo>,
    pub file_path: PathBuf,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub struct DangerousSink {
    pub function_name: String,
    pub sink_type: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub caller: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TargetAstProfile {
    pub functions: Vec<FunctionSignature>,
    pub structs: Vec<StructInfo>,
    pub dangerous_sinks: Vec<DangerousSink>,
    pub public_headers: Vec<PathBuf>,
}

pub struct AstParser {
    c_parser: tree_sitter::Parser,
}

impl AstParser {
    pub fn new() -> Result<Self, String> {
        let mut c_parser = tree_sitter::Parser::new();
        c_parser
            .set_language(&tree_sitter_c::language())
            .map_err(|e| format!("Failed to load C grammar: {e}"))?;
        Ok(Self { c_parser })
    }

    pub fn parse_file(&mut self, path: &Path) -> Result<Vec<FunctionSignature>, String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let tree = self
            .c_parser
            .parse(&content, None)
            .ok_or_else(|| format!("Failed to parse {}", path.display()))?;
        let root = tree.root_node();
        let mut functions = Vec::new();
        self.extract_functions(&root, &content, path, &mut functions);
        Ok(functions)
    }

    fn extract_functions(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        file_path: &Path,
        functions: &mut Vec<FunctionSignature>,
    ) {
        if node.kind() == "function_definition" || node.kind() == "declaration" {
            if let Some(func) = self.parse_function_node(node, content, file_path) {
                functions.push(func);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_functions(&child, content, file_path, functions);
        }
    }

    fn parse_function_node(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        file_path: &Path,
    ) -> Option<FunctionSignature> {
        let mut declarator = node.child_by_field_name("declarator")?;
        while declarator.kind() == "pointer_declarator" {
            if let Some(child) = declarator.child_by_field_name("declarator") {
                declarator = child;
            } else {
                break;
            }
        }
        let (func_name, params) = self.extract_declarator_info(&declarator, content)?;

        let return_type = node
            .child_by_field_name("type")
            .map(|t| t.utf8_text(content.as_bytes()).unwrap_or("void").to_string())
            .unwrap_or_else(|| "int".to_string());

        let has_body = node.child_by_field_name("body").is_some();
        let is_static = content[node.byte_range()].contains("static ");

        Some(FunctionSignature {
            name: func_name,
            return_type,
            parameters: params,
            file_path: file_path.to_path_buf(),
            line_number: node.start_position().row + 1,
            is_static,
            is_exported: !is_static && has_body,
            has_body,
        })
    }

    fn extract_declarator_info(
        &self,
        node: &tree_sitter::Node,
        content: &str,
    ) -> Option<(String, Vec<ParameterInfo>)> {
        let mut curr = *node;
        while curr.kind() == "pointer_declarator" {
            if let Some(child) = curr.child_by_field_name("declarator") {
                curr = child;
            } else {
                break;
            }
        }

        if curr.kind() == "function_declarator" {
            let mut direct_decl = curr.child_by_field_name("declarator")?;
            while direct_decl.kind() == "pointer_declarator" {
                if let Some(child) = direct_decl.child_by_field_name("declarator") {
                    direct_decl = child;
                } else {
                    break;
                }
            }
            let name = direct_decl.utf8_text(content.as_bytes()).ok()?.to_string();

            let mut params = Vec::new();
            if let Some(param_list) = curr.child_by_field_name("parameters") {
                let mut cursor = param_list.walk();
                for param in param_list.children(&mut cursor) {
                    if param.kind() == "parameter_declaration" {
                        let p_type = param
                            .child_by_field_name("type")
                            .map(|t| t.utf8_text(content.as_bytes()).unwrap_or("void*").to_string())
                            .unwrap_or_else(|| "void*".to_string());

                        let p_name = param
                            .child_by_field_name("declarator")
                            .map(|d| d.utf8_text(content.as_bytes()).unwrap_or("param").to_string())
                            .unwrap_or_else(|| "param".to_string());

                        let is_pointer = p_type.contains('*') || p_name.contains('*');
                        let is_const = p_type.contains("const ");

                        params.push(ParameterInfo {
                            name: p_name.trim_start_matches('*').to_string(),
                            type_name: p_type,
                            is_pointer,
                            is_const,
                        });
                    }
                }
            }
            return Some((name, params));
        }
        None
    }
}

pub fn scan_directory_ast(dir: &Path) -> Result<TargetAstProfile, String> {
    let mut parser = AstParser::new()?;
    let mut all_functions = Vec::new();
    let mut public_headers = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if let Some(ext) = path.extension() {
            if ext == "c" || ext == "cpp" || ext == "cc" || ext == "h" || ext == "hpp" {
                if ext == "h" || ext == "hpp" {
                    public_headers.push(path.to_path_buf());
                }
                if let Ok(funcs) = parser.parse_file(path) {
                    all_functions.extend(funcs);
                }
            }
        }
    }

    Ok(TargetAstProfile {
        functions: all_functions,
        structs: Vec::new(),
        dangerous_sinks: Vec::new(),
        public_headers,
    })
}
