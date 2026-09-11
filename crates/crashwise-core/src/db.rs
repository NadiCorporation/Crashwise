use crate::error::{CrashwiseError, Result};
use crate::models::{Campaign, CampaignStatus, CampaignTarget, CrashRecord, FuzzerEngine};
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
        for r in rows {
            if let Ok(c) = r {
                campaigns.push(c);
            }
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
        for r in rows {
            if let Ok(c) = r {
                crashes.push(c);
            }
        }
        Ok(crashes)
    }
}
