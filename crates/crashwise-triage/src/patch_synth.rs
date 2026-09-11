use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchCandidate {
    pub file_path: String,
    pub unified_diff: String,
    pub explanation: String,
}

pub struct PatchSynthesizer;

impl PatchSynthesizer {
    pub fn generate_bounds_check_patch(
        file_path: &str,
        func_name: &str,
        vulnerable_line: usize,
    ) -> PatchCandidate {
        let diff = format!(
            r#"--- a/{file_path}
+++ b/{file_path}
@@ -{vulnerable_line},6 +{vulnerable_line},9 @@
 void {func_name}(...) {{
+    /* CrashWise Bounds Guard */
+    if (size == 0 || size > MAX_ALLOWED_SIZE) {{
+        return -1;
+    }}
"#
        );

        PatchCandidate {
            file_path: file_path.to_string(),
            unified_diff: diff,
            explanation: format!("Added bounds check guard to prevent heap-buffer-overflow memory violation in {func_name}"),
        }
    }
}
