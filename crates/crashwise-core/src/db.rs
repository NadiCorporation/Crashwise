use crate::error::{CrashwiseError, Result};
use crate::models::{
    AgentFeedbackRecord, Campaign, CampaignStatus, CampaignTarget, CrashRecord, FuzzerEngine,
};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let parent = path.as_ref().parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;

        let conn = Connection::open(path)
            .map_err(|e| CrashwiseError::Internal(format!("Failed to open SQLite database: {e}")))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| CrashwiseError::Internal(format!("Failed to configure SQLite pragmas: {e}")))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| CrashwiseError::Internal(format!("Failed to open in-memory SQLite: {e}")))?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                target_name TEXT NOT NULL,
                target_repo TEXT NOT NULL,
                target_subdir TEXT,
                target_clone_depth INTEGER NOT NULL,
                target_commit TEXT,
                engine TEXT NOT NULL,
                status TEXT NOT NULL,
                timeout_seconds INTEGER NOT NULL,
                max_iterations INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS harnesses (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                target_function TEXT NOT NULL,
                source_path TEXT NOT NULL,
                code TEXT NOT NULL,
                binary_path TEXT,
                iteration INTEGER NOT NULL,
                compile_success INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS crashes (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                crash_type TEXT NOT NULL,
                stack_hash TEXT NOT NULL,
                stack_trace TEXT NOT NULL,
                input_path TEXT NOT NULL,
                cwe_id TEXT,
                cvss_score REAL,
                suggested_patch TEXT,
                poc_c_code TEXT,
                verified INTEGER NOT NULL,
                found_at TEXT NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS fuzz_runs (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                iteration INTEGER NOT NULL,
                executions INTEGER NOT NULL,
                coverage_edges INTEGER NOT NULL,
                duration_seconds REAL NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );

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
                success_count INTEGER DEFAULT 1,
                failure_count INTEGER DEFAULT 0,
                score REAL DEFAULT 1.0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_feedback_type ON agent_feedback_memory(feedback_type);
            CREATE INDEX IF NOT EXISTS idx_feedback_target ON agent_feedback_memory(target_name);
            CREATE INDEX IF NOT EXISTS idx_feedback_error_cat ON agent_feedback_memory(error_category);
            CREATE INDEX IF NOT EXISTS idx_feedback_score ON agent_feedback_memory(score DESC);
            CREATE INDEX IF NOT EXISTS idx_feedback_created ON agent_feedback_memory(created_at DESC);
            "#,
        )
        .map_err(|e| CrashwiseError::Internal(format!("Failed to initialize database schema: {e}")))?;
        Ok(())
    }


    pub fn insert_campaign(&self, campaign: &Campaign) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let engine_str = serde_json::to_string(&campaign.engine)
            .unwrap_or_else(|_| "libfuzzer".to_string())
            .replace('"', "");
        let status_str = serde_json::to_string(&campaign.status)
            .unwrap_or_else(|_| "pending".to_string())
            .replace('"', "");

        conn.execute(
            r#"INSERT INTO campaigns (
                id, target_name, target_repo, target_subdir, target_clone_depth, target_commit,
                engine, status, timeout_seconds, max_iterations, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
            params![
                campaign.id.to_string(),
                campaign.target.name,
                campaign.target.repo_url,
                campaign.target.subdir,
                campaign.target.clone_depth,
                campaign.target.commit_hash,
                engine_str,
                status_str,
                campaign.timeout_seconds,
                campaign.max_iterations,
                campaign.created_at.to_rfc3339(),
                campaign.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| CrashwiseError::Internal(format!("Failed to insert campaign: {e}")))?;
        Ok(())
    }

    pub fn update_campaign_status(&self, id: Uuid, status: CampaignStatus) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let status_str = serde_json::to_string(&status)
            .unwrap_or_else(|_| "pending".to_string())
            .replace('"', "");
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE campaigns SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status_str, now, id.to_string()],
        )
        .map_err(|e| CrashwiseError::Internal(format!("Failed to update campaign status: {e}")))?;
        Ok(())
    }

    pub fn list_campaigns(&self) -> Result<Vec<Campaign>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, target_name, target_repo, target_subdir, target_clone_depth, target_commit, engine, status, timeout_seconds, max_iterations, created_at, updated_at FROM campaigns ORDER BY created_at DESC")
            .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare query: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                let id_str: String = row.get(0)?;
                let id = Uuid::parse_str(&id_str).unwrap_or_default();
                let target_name: String = row.get(1)?;
                let target_repo: String = row.get(2)?;
                let target_subdir: Option<String> = row.get(3)?;
                let target_clone_depth: u32 = row.get(4)?;
                let target_commit: Option<String> = row.get(5)?;
                let engine_str: String = row.get(6)?;
                let status_str: String = row.get(7)?;
                let timeout_seconds: u64 = row.get(8)?;
                let max_iterations: u32 = row.get(9)?;
                let created_at_str: String = row.get(10)?;
                let updated_at_str: String = row.get(11)?;

                let engine = serde_json::from_str(&format!("\"{}\"", engine_str)).unwrap_or(FuzzerEngine::Libfuzzer);
                let status = serde_json::from_str(&format!("\"{}\"", status_str)).unwrap_or(CampaignStatus::Pending);
                let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(Campaign {
                    id,
                    target: CampaignTarget {
                        name: target_name,
                        repo_url: target_repo,
                        subdir: target_subdir,
                        clone_depth: target_clone_depth,
                        commit_hash: target_commit,
                    },
                    engine,
                    status,
                    timeout_seconds,
                    max_iterations,
                    created_at,
                    updated_at,
                })
            })
            .map_err(|e| CrashwiseError::Internal(format!("Failed to query campaigns: {e}")))?;

        let mut campaigns = Vec::new();
        for c in rows.flatten() {
            campaigns.push(c);
        }
        Ok(campaigns)
    }

    pub fn insert_crash(&self, crash: &CrashRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO crashes (
                id, campaign_id, crash_type, stack_hash, stack_trace, input_path,
                cwe_id, cvss_score, suggested_patch, poc_c_code, verified, found_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
            params![
                crash.id.to_string(),
                crash.campaign_id.to_string(),
                crash.crash_type,
                crash.stack_hash,
                crash.stack_trace,
                crash.input_path.to_string_lossy().to_string(),
                crash.cwe_id,
                crash.cvss_score,
                crash.suggested_patch,
                crash.poc_c_code,
                if crash.verified { 1 } else { 0 },
                crash.found_at.to_rfc3339(),
            ],
        )
        .map_err(|e| CrashwiseError::Internal(format!("Failed to insert crash: {e}")))?;
        Ok(())
    }

    pub fn list_crashes(&self, campaign_id: Option<Uuid>) -> Result<Vec<CrashRecord>> {
        let conn = self.conn.lock().unwrap();
        let query = if campaign_id.is_some() {
            "SELECT id, campaign_id, crash_type, stack_hash, stack_trace, input_path, cwe_id, cvss_score, suggested_patch, poc_c_code, verified, found_at FROM crashes WHERE campaign_id = ?1 ORDER BY found_at DESC"
        } else {
            "SELECT id, campaign_id, crash_type, stack_hash, stack_trace, input_path, cwe_id, cvss_score, suggested_patch, poc_c_code, verified, found_at FROM crashes ORDER BY found_at DESC"
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare crashes query: {e}")))?;

        let cid_str = campaign_id.map(|id| id.to_string());
        let params_vec: Vec<&dyn rusqlite::ToSql> = if let Some(ref cid) = cid_str {
            vec![cid]
        } else {
            vec![]
        };

        let rows = stmt
            .query_map(rusqlite::params_from_iter(params_vec), |row| {
                let id_str: String = row.get(0)?;
                let cid_str: String = row.get(1)?;
                let crash_type: String = row.get(2)?;
                let stack_hash: String = row.get(3)?;
                let stack_trace: String = row.get(4)?;
                let input_path_str: String = row.get(5)?;
                let cwe_id: Option<String> = row.get(6)?;
                let cvss_score: Option<f32> = row.get(7)?;
                let suggested_patch: Option<String> = row.get(8)?;
                let poc_c_code: Option<String> = row.get(9)?;
                let verified_int: i32 = row.get(10)?;
                let found_at_str: String = row.get(11)?;

                let found_at = DateTime::parse_from_rfc3339(&found_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(CrashRecord {
                    id: Uuid::parse_str(&id_str).unwrap_or_default(),
                    campaign_id: Uuid::parse_str(&cid_str).unwrap_or_default(),
                    crash_type,
                    stack_hash,
                    stack_trace,
                    input_path: PathBuf::from(input_path_str),
                    cwe_id,
                    cvss_score,
                    suggested_patch,
                    poc_c_code,
                    verified: verified_int == 1,
                    found_at,
                })
            })
            .map_err(|e| CrashwiseError::Internal(format!("Failed to query crashes: {e}")))?;

        let mut crashes = Vec::new();
        for c in rows.flatten() {
            crashes.push(c);
        }
        Ok(crashes)
    }


    fn row_to_feedback_record(row: &rusqlite::Row) -> rusqlite::Result<AgentFeedbackRecord> {
        let id_str: String = row.get(0)?;
        let cid_str: Option<String> = row.get(1)?;
        let target_name: String = row.get(2)?;
        let feedback_type: String = row.get(3)?;
        let compiler_diagnostic: Option<String> = row.get(4)?;
        let error_category: Option<String> = row.get(5)?;
        let original_code: Option<String> = row.get(6)?;
        let resolved_code: Option<String> = row.get(7)?;
        let tokens_str: Option<String> = row.get(8)?;
        let success_count: u32 = row.get(9)?;
        let failure_count: u32 = row.get(10)?;
        let score: f32 = row.get(11)?;
        let created_at_str: String = row.get(12)?;
        let updated_at_str: String = row.get(13)?;

        let coverage_tokens = tokens_str.and_then(|s| serde_json::from_str(&s).ok());
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(AgentFeedbackRecord {
            id: Uuid::parse_str(&id_str).unwrap_or_default(),
            campaign_id: cid_str.and_then(|s| Uuid::parse_str(&s).ok()),
            target_name,
            feedback_type,
            compiler_diagnostic,
            error_category,
            original_code,
            resolved_code,
            coverage_tokens,
            success_count,
            failure_count,
            score,
            created_at,
            updated_at,
        })
    }

    pub fn insert_feedback_record(&self, record: &AgentFeedbackRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let cid_str = record.campaign_id.map(|id| id.to_string());
        let tokens_json = record.coverage_tokens.as_ref().map(|tokens| {
            serde_json::to_string(tokens).unwrap_or_else(|_| "[]".to_string())
        });

        conn.execute(
            r#"INSERT INTO agent_feedback_memory (
                id, campaign_id, target_name, feedback_type, compiler_diagnostic,
                error_category, original_code, resolved_code, coverage_tokens,
                success_count, failure_count, score, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"#,
            params![
                record.id.to_string(),
                cid_str,
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
                record.created_at.to_rfc3339(),
                record.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| CrashwiseError::Internal(format!("Failed to insert feedback record: {e}")))?;
        Ok(())
    }

    pub fn record_resolved_fix(
        &self,
        campaign_id: Option<Uuid>,
        target_name: &str,
        diagnostic: &str,
        original_code: &str,
        resolved_code: &str,
    ) -> Result<Uuid> {
        let now = Utc::now();
        let category = classify_compiler_error(diagnostic);
        let id = Uuid::new_v4();
        let record = AgentFeedbackRecord {
            id,
            campaign_id,
            target_name: target_name.to_string(),
            feedback_type: "resolved_fix".to_string(),
            compiler_diagnostic: Some(diagnostic.to_string()),
            error_category: Some(category),
            original_code: Some(original_code.to_string()),
            resolved_code: Some(resolved_code.to_string()),
            coverage_tokens: None,
            success_count: 1,
            failure_count: 0,
            score: 1.0,
            created_at: now,
            updated_at: now,
        };
        self.insert_feedback_record(&record)?;
        Ok(id)
    }

    pub fn record_coverage_tokens(
        &self,
        campaign_id: Option<Uuid>,
        target_name: &str,
        tokens: &[String],
    ) -> Result<Uuid> {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let record = AgentFeedbackRecord {
            id,
            campaign_id,
            target_name: target_name.to_string(),
            feedback_type: "coverage_token".to_string(),
            compiler_diagnostic: None,
            error_category: None,
            original_code: None,
            resolved_code: None,
            coverage_tokens: Some(tokens.to_vec()),
            success_count: 1,
            failure_count: 0,
            score: 1.0,
            created_at: now,
            updated_at: now,
        };
        self.insert_feedback_record(&record)?;
        Ok(id)
    }

    pub fn query_similar_compiler_fixes(
        &self,
        diagnostic: &str,
        target_name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AgentFeedbackRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                r#"SELECT id, campaign_id, target_name, feedback_type, compiler_diagnostic,
                          error_category, original_code, resolved_code, coverage_tokens,
                          success_count, failure_count, score, created_at, updated_at
                   FROM agent_feedback_memory
                   WHERE feedback_type = 'resolved_fix'
                   ORDER BY score DESC, created_at DESC"#,
            )
            .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare query: {e}")))?;

        let records_iter = stmt
            .query_map([], Self::row_to_feedback_record)
            .map_err(|e| CrashwiseError::Internal(format!("Failed to query feedback: {e}")))?;

        let mut records = Vec::new();
        for rec in records_iter.flatten() {
            records.push(rec);
        }


        if records.is_empty() {
            return Ok(Vec::new());
        }

        let input_cat = classify_compiler_error(diagnostic);
        let diag_words: std::collections::HashSet<String> = diagnostic
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .map(|w| w.to_lowercase())
            .filter(|w| {
                w.len() >= 3 && !matches!(w.as_str(), "the" | "and" | "for" | "with" | "from" | "error" | "note")
            })
            .collect();

        let mut scored: Vec<(f32, AgentFeedbackRecord)> = records
            .into_iter()
            .map(|rec| {
                let mut rel = rec.score;
                if let Some(target) = target_name {
                    if rec.target_name.eq_ignore_ascii_case(target) {
                        rel += 5.0;
                    }
                }
                if let Some(ref cat) = rec.error_category {
                    if cat == &input_cat {
                        rel += 3.0;
                    }
                }
                if let Some(ref d) = rec.compiler_diagnostic {
                    let rec_words: std::collections::HashSet<String> = d
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .map(|w| w.to_lowercase())
                        .filter(|w| w.len() >= 3)
                        .collect();
                    let overlap = diag_words.intersection(&rec_words).count();
                    rel += overlap as f32 * 2.0;
                }
                (rel, rec)
            })
            .collect();

        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let results = scored.into_iter().take(limit).map(|(_, r)| r).collect();
        Ok(results)
    }

    pub fn query_harness_exemplars(
        &self,
        target_name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AgentFeedbackRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut exemplars = Vec::new();

        if let Some(target) = target_name {
            let mut stmt = conn
                .prepare(
                    r#"SELECT id, campaign_id, target_name, feedback_type, compiler_diagnostic,
                              error_category, original_code, resolved_code, coverage_tokens,
                              success_count, failure_count, score, created_at, updated_at
                       FROM agent_feedback_memory
                       WHERE feedback_type = 'harness_exemplar' AND target_name = ?1
                       ORDER BY score DESC, created_at DESC
                       LIMIT ?2"#,
                )
                .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare query: {e}")))?;

            let rows = stmt
                .query_map(params![target, limit as i64], Self::row_to_feedback_record)
                .map_err(|e| CrashwiseError::Internal(format!("Failed to query exemplars: {e}")))?;

            for rec in rows.flatten() {
                exemplars.push(rec);
            }
        }

        if exemplars.len() < limit {
            let remaining = limit - exemplars.len();
            let existing_ids: std::collections::HashSet<Uuid> = exemplars.iter().map(|e| e.id).collect();

            let mut stmt = conn
                .prepare(
                    r#"SELECT id, campaign_id, target_name, feedback_type, compiler_diagnostic,
                              error_category, original_code, resolved_code, coverage_tokens,
                              success_count, failure_count, score, created_at, updated_at
                       FROM agent_feedback_memory
                       WHERE feedback_type = 'harness_exemplar'
                       ORDER BY score DESC, created_at DESC
                       LIMIT ?1"#,
                )
                .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare query: {e}")))?;

            let rows = stmt
                .query_map(params![(remaining * 2 + 5) as i64], Self::row_to_feedback_record)
                .map_err(|e| CrashwiseError::Internal(format!("Failed to query exemplars: {e}")))?;

            for rec in rows.flatten() {
                if !existing_ids.contains(&rec.id) {
                    exemplars.push(rec);
                    if exemplars.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(exemplars)
    }

    pub fn query_coverage_tokens(
        &self,
        target_name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let rows_data: Vec<Option<String>> = if let Some(target) = target_name {
            let mut stmt = conn
                .prepare(
                    r#"SELECT coverage_tokens FROM agent_feedback_memory
                       WHERE feedback_type = 'coverage_token' AND (target_name = ?1 OR target_name = '*')
                       ORDER BY score DESC, created_at DESC"#,
                )
                .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare query: {e}")))?;
            let rows = stmt
                .query_map(params![target], |row| row.get::<_, Option<String>>(0))
                .map_err(|e| CrashwiseError::Internal(format!("Failed to query coverage tokens: {e}")))?;
            rows.filter_map(|r| r.ok()).collect()
        } else {
            let mut stmt = conn
                .prepare(
                    r#"SELECT coverage_tokens FROM agent_feedback_memory
                       WHERE feedback_type = 'coverage_token'
                       ORDER BY score DESC, created_at DESC"#,
                )
                .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare query: {e}")))?;
            let rows = stmt
                .query_map([], |row| row.get::<_, Option<String>>(0))
                .map_err(|e| CrashwiseError::Internal(format!("Failed to query coverage tokens: {e}")))?;
            rows.filter_map(|r| r.ok()).collect()
        };

        let mut tokens = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for s in rows_data.into_iter().flatten() {
            if let Ok(tok_list) = serde_json::from_str::<Vec<String>>(&s) {
                for t in tok_list {
                    if seen.insert(t.clone()) {
                        tokens.push(t);
                        if tokens.len() >= limit {
                            return Ok(tokens);
                        }
                    }
                }
            }
        }


        Ok(tokens)
    }

    pub fn table_exists(&self, table_name: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare query: {e}")))?;
        let exists = stmt
            .exists(params![table_name])
            .map_err(|e| CrashwiseError::Internal(format!("Failed to check table: {e}")))?;
        Ok(exists)
    }

    pub fn index_exists(&self, index_name: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1")
            .map_err(|e| CrashwiseError::Internal(format!("Failed to prepare query: {e}")))?;
        let exists = stmt
            .exists(params![index_name])
            .map_err(|e| CrashwiseError::Internal(format!("Failed to check index: {e}")))?;
        Ok(exists)
    }
}


pub fn classify_compiler_error(diag: &str) -> String {
    let lower = diag.to_lowercase();
    if lower.contains("no such file")
        || lower.contains("file not found")
        || lower.contains("cannot open include")
    {
        "missing_header".to_string()
    } else if lower.contains("undeclared")
        || lower.contains("undefined symbol")
        || lower.contains("undefined reference")
        || lower.contains("unknown type name")
    {
        "undefined_symbol".to_string()
    } else if lower.contains("incompatible")
        || lower.contains("cannot convert")
        || lower.contains("type mismatch")
        || lower.contains("invalid conversion")
    {
        "type_mismatch".to_string()
    } else if lower.contains("too few arguments")
        || lower.contains("too many arguments")
        || lower.contains("argument mismatch")
    {
        "argument_mismatch".to_string()
    } else if lower.contains("syntax error")
        || lower.contains("expected ';'")
        || lower.contains("expected ')'")
    {
        "syntax_error".to_string()
    } else if lower.contains("conflicting types") || lower.contains("redefinition") {
        "redefinition".to_string()
    } else {
        "compiler_error".to_string()
    }
}

