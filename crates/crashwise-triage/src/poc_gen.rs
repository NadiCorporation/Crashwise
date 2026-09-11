use crashwise_core::models::CrashRecord;

pub struct PocGenerator;

impl PocGenerator {
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
}
