use crashwise_core::models::CrashRecord;
use md5::{Digest, Md5};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    pub frame_num: usize,
    pub address: String,
    pub function: String,
    pub source_file: Option<String>,
    pub line_number: Option<usize>,
}

pub struct AsanParser;

impl AsanParser {
    /// Parse an AddressSanitizer or sanitizer crash log into a `CrashRecord`.
    /// Note: `verified` is set to `false` initially, awaiting closed-loop patch verification.
    pub fn parse_asan_log(campaign_id: Uuid, log_text: &str, crash_input_path: &Path) -> Option<CrashRecord> {
        let crash_type_re = Regex::new(r"ERROR:\s*AddressSanitizer:\s*([a-zA-Z0-9_\-]+)").unwrap();
        let crash_type = crash_type_re
            .captures(log_text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .or_else(|| Self::detect_sanitizer_violation(log_text))
            .unwrap_or_else(|| "Unknown-Crash".to_string());

        let frame_header_re = Regex::new(r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+([^\r\n]+)").unwrap();
        let loc_re = Regex::new(r"^(.*?)\s+([^\s:]+):(\d+)$").unwrap();
        let mut top_frames = Vec::new();
        for caps in frame_header_re.captures_iter(log_text).take(4) {
            let raw_desc = caps.get(3).map(|m| m.as_str().trim()).unwrap_or_default();
            let func = if let Some(loc_caps) = loc_re.captures(raw_desc) {
                loc_caps.get(1).map(|m| m.as_str().trim()).unwrap_or_default()
            } else {
                raw_desc
            };
            top_frames.push(func);
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
            verified: false,
            found_at: chrono::Utc::now(),
        })
    }

    /// Extract source file path and line number from the top-most stack frame that includes source location.
    /// Matches format: `#\d+\s+0x[0-9a-fA-F]+\s+in\s+([^\s:]+)\s+([^\s:]+):(\d+)` and C++ signatures.
    pub fn extract_source_location(log_text: &str) -> Option<(String, usize)> {
        let re = Regex::new(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?:.*?)\s+([^\s:]+):(\d+)").unwrap();
        if let Some(caps) = re.captures(log_text) {
            let file = caps.get(1)?.as_str().to_string();
            let line = caps.get(2)?.as_str().parse::<usize>().ok()?;
            return Some((file, line));
        }
        None
    }

    /// Extract all source locations (file, line) present across all stack frames.
    pub fn extract_all_source_locations(log_text: &str) -> Vec<(String, usize)> {
        let re = Regex::new(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?:.*?)\s+([^\s:]+):(\d+)").unwrap();
        let mut results = Vec::new();
        for caps in re.captures_iter(log_text) {
            if let (Some(f), Some(l)) = (caps.get(1), caps.get(2)) {
                if let Ok(line_num) = l.as_str().parse::<usize>() {
                    results.push((f.as_str().to_string(), line_num));
                }
            }
        }
        results
    }

    /// Parse detailed stack frames from log text.
    pub fn parse_stack_frames(log_text: &str) -> Vec<StackFrame> {
        let frame_header_re = Regex::new(r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+([^\r\n]+)").unwrap();
        let loc_re = Regex::new(r"^(.*?)\s+([^\s:]+):(\d+)$").unwrap();
        let mut frames = Vec::new();
        for caps in frame_header_re.captures_iter(log_text) {
            let frame_num = caps.get(1).and_then(|m| m.as_str().parse::<usize>().ok()).unwrap_or(0);
            let address = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
            let raw_desc = caps.get(3).map(|m| m.as_str().trim()).unwrap_or_default();

            let (function, source_file, line_number) = if let Some(loc_caps) = loc_re.captures(raw_desc) {
                let func = loc_caps.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                let file = loc_caps.get(2).map(|m| m.as_str().to_string());
                let line = loc_caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok());
                (func, file, line)
            } else {
                (raw_desc.to_string(), None, None)
            };

            frames.push(StackFrame {
                frame_num,
                address,
                function,
                source_file,
                line_number,
            });
        }
        frames
    }

    /// Detect sanitizer violation signatures from execution output (stdout/stderr).
    pub fn detect_sanitizer_violation(output: &str) -> Option<String> {
        // Match ERROR: AddressSanitizer: <violation>
        let asan_re = Regex::new(r"ERROR:\s*AddressSanitizer:\s*([a-zA-Z0-9_\-]+)").unwrap();
        if let Some(caps) = asan_re.captures(output) {
            if let Some(m) = caps.get(1) {
                return Some(m.as_str().to_string());
            }
        }

        // Match SUMMARY: AddressSanitizer: <violation>
        let summary_re = Regex::new(r"SUMMARY:\s*([a-zA-Z0-9_\-]+Sanitizer):\s*([a-zA-Z0-9_\-]+)").unwrap();
        if let Some(caps) = summary_re.captures(output) {
            if let (Some(san), Some(viol)) = (caps.get(1), caps.get(2)) {
                return Some(format!("{}: {}", san.as_str(), viol.as_str()));
            }
        }

        // Match UndefinedBehaviorSanitizer: runtime error: <violation>
        let ubsan_re = Regex::new(r"runtime error:\s*([^\n\r]+)").unwrap();
        if let Some(caps) = ubsan_re.captures(output) {
            if let Some(m) = caps.get(1) {
                return Some(format!("UndefinedBehaviorSanitizer: {}", m.as_str().trim()));
            }
        }

        // Match other sanitizers: MemorySanitizer, ThreadSanitizer, LeakSanitizer
        let other_re = Regex::new(r"(?:ERROR|WARNING):\s*(MemorySanitizer|ThreadSanitizer|LeakSanitizer):\s*([a-zA-Z0-9_\-]+)").unwrap();
        if let Some(caps) = other_re.captures(output) {
            if let (Some(san), Some(viol)) = (caps.get(1), caps.get(2)) {
                return Some(format!("{}: {}", san.as_str(), viol.as_str()));
            }
        }

        // Match general AddressSanitizer banner
        if output.contains("AddressSanitizer:") {
            let gen_re = Regex::new(r"AddressSanitizer:\s*([a-zA-Z0-9_\-]+)").unwrap();
            if let Some(caps) = gen_re.captures(output) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().to_string());
                }
            }
            return Some("AddressSanitizer-Violation".to_string());
        }

        None
    }

    /// Check if execution is clean: exited with code 0 and has zero sanitizer/crash markers.
    pub fn is_clean_execution(output: &str, exit_status: Option<i32>) -> bool {
        if exit_status != Some(0) {
            return false;
        }

        if Self::detect_sanitizer_violation(output).is_some() {
            return false;
        }

        let forbidden = [
            "AddressSanitizer",
            "LeakSanitizer",
            "MemorySanitizer",
            "ThreadSanitizer",
            "runtime error:",
            "Segmentation fault",
            "Aborted (core dumped)",
            "Assertion failed",
            "fatal error",
        ];

        for marker in &forbidden {
            if output.contains(marker) {
                return false;
            }
        }

        true
    }

    pub fn score_vulnerability(crash_type: &str) -> (String, f32) {
        if crash_type.contains("heap-use-after-free") {
            ("CWE-416".to_string(), 9.1)
        } else if crash_type.contains("heap-buffer-overflow") {
            ("CWE-122".to_string(), 8.8)
        } else if crash_type.contains("stack-buffer-overflow") {
            ("CWE-121".to_string(), 8.6)
        } else if crash_type.contains("global-buffer-overflow") {
            ("CWE-120".to_string(), 7.5)
        } else if crash_type.contains("use-after-poison") {
            ("CWE-825".to_string(), 7.8)
        } else if crash_type.contains("double-free") {
            ("CWE-415".to_string(), 8.1)
        } else {
            ("CWE-119".to_string(), 7.0)
        }
    }
}
