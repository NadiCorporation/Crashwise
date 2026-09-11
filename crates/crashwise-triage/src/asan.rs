use crashwise_core::models::CrashRecord;
use md5::{Digest, Md5};
use regex::Regex;
use std::path::Path;
use uuid::Uuid;

pub struct AsanParser;

impl AsanParser {
    pub fn parse_asan_log(campaign_id: Uuid, log_text: &str, crash_input_path: &Path) -> Option<CrashRecord> {
        let crash_type_re = Regex::new(r"ERROR:\s*AddressSanitizer:\s*([a-zA-Z0-9_\-]+)").unwrap();
        let crash_type = crash_type_re
            .captures(log_text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown-Crash".to_string());

        let frame_re = Regex::new(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+([a-zA-Z0-9_]+)").unwrap();
        let mut top_frames = Vec::new();
        for cap in frame_re.captures_iter(log_text).take(4) {
            if let Some(f) = cap.get(1) {
                top_frames.push(f.as_str());
            }
        }

        let mut hasher = Md5::new();
        if !top_frames.is_empty() {
            hasher.update(top_frames.join(":").as_bytes());
        } else {
            hasher.update(crash_type.as_bytes());
        }
        let stack_hash = format!("{:x}", hasher.finalize());

        let (cwe, cvss) = Self::score_vulnerability(&crash_type);

        Some(CrashRecord {
            id: Uuid::new_v4(),
            campaign_id,
            crash_type,
            stack_hash,
            stack_trace: log_text.to_string(),
            input_path: crash_input_path.to_path_buf(),
            cwe_id: Some(cwe),
            cvss_score: Some(cvss),
            suggested_patch: None,
            poc_c_code: None,
            verified: true,
            found_at: chrono::Utc::now(),
        })
    }

    fn score_vulnerability(crash_type: &str) -> (String, f32) {
        match crash_type {
            "heap-buffer-overflow" => ("CWE-122".to_string(), 8.8),
            "stack-buffer-overflow" => ("CWE-121".to_string(), 8.6),
            "heap-use-after-free" => ("CWE-416".to_string(), 9.1),
            "global-buffer-overflow" => ("CWE-120".to_string(), 7.5),
            "use-after-poison" => ("CWE-825".to_string(), 7.8),
            "double-free" => ("CWE-415".to_string(), 8.1),
            _ => ("CWE-119".to_string(), 7.0),
        }
    }
}
