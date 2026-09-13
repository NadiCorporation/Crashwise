use crashwise_agent::{HarnessSynthesizer, MockLlmClient, SanityGate};
use crashwise_ast::types::{FunctionSignature, ParameterInfo};
use crashwise_core::db::Database;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;

fn build_test_harness_binary(src_code: &str, out_bin: &Path) {
    let temp_src = out_bin.with_extension("cpp");
    std::fs::write(&temp_src, src_code).expect("Failed to write test harness source");

    let status = Command::new("clang++")
        .arg("-O1")
        .arg("-g")
        .arg("-fsanitize=fuzzer,address,undefined")
        .arg(&temp_src)
        .arg("-o")
        .arg(out_bin)
        .status()
        .expect("Failed to invoke clang++ to compile challenge test harness");

    assert!(status.success(), "Challenge harness failed to compile with clang++");
}

#[tokio::test]
async fn test_sanity_gate_hardware_segfault_rejected() {
    let temp = tempdir().expect("Failed to create tempdir");
    let harness_bin = temp.path().join("harness_segfault");

    let segfault_code = r#"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) {
        volatile int *null_ptr = (volatile int *)0x0;
        *null_ptr = 1337;
    }
    return 0;
}
"#;

    build_test_harness_binary(segfault_code, &harness_bin);
    assert!(harness_bin.exists());

    // 1. Direct SanityGate verification
    let result = SanityGate::verify_harness_binary(&harness_bin).await;
    assert!(result.is_err(), "SanityGate must reject segfaulting harness");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Harness crashed during 5-second sanity run")
            || err_msg.contains("SEGV")
            || err_msg.contains("AddressSanitizer"),
        "Error message should mention crash/SEGV/AddressSanitizer: {}",
        err_msg
    );

    // 2. Synthesizer loop with Database: verify NO harness exemplar is saved
    let db = Database::open_in_memory().expect("Failed to open DB");
    let mock_llm = Arc::new(MockLlmClient::new(vec![
        format!("```cpp\n{}\n```", segfault_code),
        format!("```cpp\n{}\n```", segfault_code),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm)
        .with_db(db.clone())
        .with_target_name("segfault_target")
        .with_max_retries(2);

    let dummy_func = FunctionSignature {
        name: "test_segfault".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("test.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let synth_res = synth
        .synthesize_and_validate(&dummy_func, &[], &[], temp.path())
        .await;

    assert!(synth_res.is_err(), "Synthesis must fail after retrying segfaulting harness");

    let exemplars = db
        .query_harness_exemplars(Some("segfault_target"), 10)
        .expect("Query exemplars");
    assert_eq!(
        exemplars.len(),
        0,
        "Segfaulting harness must NOT be saved as a valid exemplar in SQLite"
    );
}

#[tokio::test]
async fn test_sanity_gate_nonzero_exit_code_rejected() {
    let temp = tempdir().expect("Failed to create tempdir");
    let harness_bin = temp.path().join("harness_exit_42");

    let exit_code = r#"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) {
        exit(42);
    }
    return 0;
}
"#;

    build_test_harness_binary(exit_code, &harness_bin);

    // 1. Direct SanityGate verification
    let result = SanityGate::verify_harness_binary(&harness_bin).await;
    assert!(result.is_err(), "SanityGate must reject harness exiting with non-zero code");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Harness execution failed during sanity run")
            && (err_msg.contains("exit code Some(77)") || err_msg.contains("fuzz target exited")),
        "Error message should capture libFuzzer target exit error: {}",
        err_msg
    );

    // 2. Synthesizer loop with Database: verify NO harness exemplar is saved
    let db = Database::open_in_memory().expect("Failed to open DB");
    let mock_llm = Arc::new(MockLlmClient::new(vec![
        format!("```cpp\n{}\n```", exit_code),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm)
        .with_db(db.clone())
        .with_target_name("exit_target")
        .with_max_retries(1);

    let dummy_func = FunctionSignature {
        name: "test_exit".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("test.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let synth_res = synth
        .synthesize_and_validate(&dummy_func, &[], &[], temp.path())
        .await;

    assert!(synth_res.is_err());
    let exemplars = db
        .query_harness_exemplars(Some("exit_target"), 10)
        .expect("Query exemplars");
    assert_eq!(
        exemplars.len(),
        0,
        "Harness with non-zero exit code must NOT be saved as an exemplar in SQLite"
    );
}

#[tokio::test]
async fn test_sanity_gate_abort_signal_rejected() {
    let temp = tempdir().expect("Failed to create tempdir");
    let harness_bin = temp.path().join("harness_abort");

    let abort_code = r#"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) {
        abort();
    }
    return 0;
}
"#;

    build_test_harness_binary(abort_code, &harness_bin);

    let result = SanityGate::verify_harness_binary(&harness_bin).await;
    assert!(result.is_err(), "SanityGate must reject harness calling abort()");

    let db = Database::open_in_memory().expect("Failed to open DB");
    let mock_llm = Arc::new(MockLlmClient::new(vec![
        format!("```cpp\n{}\n```", abort_code),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm)
        .with_db(db.clone())
        .with_target_name("abort_target")
        .with_max_retries(1);

    let dummy_func = FunctionSignature {
        name: "test_abort".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("test.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let synth_res = synth
        .synthesize_and_validate(&dummy_func, &[], &[], temp.path())
        .await;

    assert!(synth_res.is_err());
    let exemplars = db
        .query_harness_exemplars(Some("abort_target"), 10)
        .expect("Query exemplars");
    assert_eq!(exemplars.len(), 0, "Aborting harness must not be saved");
}

#[tokio::test]
async fn test_sanity_gate_infinite_loop_timeout_rejected() {
    let temp = tempdir().expect("Failed to create tempdir");
    let harness_bin = temp.path().join("harness_timeout");

    let loop_code = r#"
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) {
        volatile int running = 1;
        while (running) {
            usleep(1000);
        }
    }
    return 0;
}
"#;

    build_test_harness_binary(loop_code, &harness_bin);

    // 1. Direct SanityGate verification (waits for 6-second timeout)
    let result = SanityGate::verify_harness_binary(&harness_bin).await;
    assert!(result.is_err(), "SanityGate must reject harness timing out in infinite loop");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Sanity gate timeout (infinite loop detected)"),
        "Error message should explicitly diagnose infinite loop timeout: {}",
        err_msg
    );

    // 2. Synthesizer loop with Database: verify NO harness exemplar is saved
    let db = Database::open_in_memory().expect("Failed to open DB");
    let mock_llm = Arc::new(MockLlmClient::new(vec![
        format!("```cpp\n{}\n```", loop_code),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm)
        .with_db(db.clone())
        .with_target_name("timeout_target")
        .with_max_retries(1);

    let dummy_func = FunctionSignature {
        name: "test_timeout".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("test.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let synth_res = synth
        .synthesize_and_validate(&dummy_func, &[], &[], temp.path())
        .await;

    assert!(synth_res.is_err());
    let exemplars = db
        .query_harness_exemplars(Some("timeout_target"), 10)
        .expect("Query exemplars");
    assert_eq!(
        exemplars.len(),
        0,
        "Timed-out harness must NOT be saved as an exemplar in SQLite"
    );
}

#[test]
fn test_harness_path_and_header_inference_assumptions() {
    // 1. Check path inference across targets
    assert_eq!(
        HarnessSynthesizer::infer_target_name(Path::new("/usr/src/cjson/cJSON.c")),
        Some("cJSON".to_string())
    );
    assert_eq!(
        HarnessSynthesizer::infer_target_name(Path::new("targets/zlib/deflate.c")),
        Some("zlib".to_string())
    );
    assert_eq!(
        HarnessSynthesizer::infer_target_name(Path::new("vendor/libpng/pngread.c")),
        Some("libpng".to_string())
    );
    assert_eq!(
        HarnessSynthesizer::infer_target_name(Path::new("submodules/sqlite/sqlite3.c")),
        Some("sqlite3".to_string())
    );

    // 2. Check header inference heuristics
    let header_cjson = crashwise_agent::ExemplarRetriever::infer_target_header(Path::new("cJSON.c"));
    assert_eq!(header_cjson, Some("cJSON.h".to_string()));

    let header_already_h = crashwise_agent::ExemplarRetriever::infer_target_header(Path::new("sqlite3.h"));
    assert_eq!(header_already_h, Some("sqlite3.h".to_string()));

    // 3. Verify no hardcoded system paths in generated deterministic harness
    let func = FunctionSignature {
        name: "cJSON_Parse".to_string(),
        return_type: "cJSON *".to_string(),
        parameters: vec![ParameterInfo {
            name: "value".to_string(),
            type_name: "char".to_string(),
            is_pointer: true,
            is_const: true,
        }],
        file_path: PathBuf::from("cJSON.c"),
        line_number: 10,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let generated = HarnessSynthesizer::synthesize_deterministic_harness(&func, Some("cJSON"), Some("cJSON.h"));

    assert!(!generated.contains("/home/"), "Harness must not contain hardcoded home paths");
    assert!(!generated.contains("/tmp/"), "Harness must not contain hardcoded /tmp/ paths");
    assert!(!generated.contains("/usr/"), "Harness must not contain hardcoded /usr/ paths");
    assert!(generated.contains("#include <cJSON.h>"), "Harness should use standard angle bracket include");
}

#[tokio::test]
async fn test_compilation_rate_benchmark_empirical_analysis() {
    // Re-run the exact 11 target cases from test_compilation_rate_benchmark
    // to empirically capture pass/fail distribution and identify root causes
    let temp = tempdir().expect("Failed to create tempdir");
    let include_dir = temp.path().join("include");
    std::fs::create_dir_all(&include_dir).unwrap();
    let out_dir = temp.path().join("build");
    std::fs::create_dir_all(&out_dir).unwrap();

    // Create benchmark headers
    let cjson_h = r#"#ifndef CJSON_H
#define CJSON_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct cJSON {
    struct cJSON *next;
    int type;
} cJSON;
cJSON *cJSON_Parse(const char *value);
cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length);
char *cJSON_Print(const cJSON *item);
char *cJSON_PrintUnformatted(const cJSON *item);
void cJSON_Delete(cJSON *item);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(include_dir.join("cJSON.h"), cjson_h).unwrap();

    let zlib_h = r#"#ifndef ZLIB_H
#define ZLIB_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef unsigned char Bytef;
typedef unsigned long uLongf;
typedef unsigned long uLong;
typedef struct z_stream_s {
    Bytef *next_in;
    uLong avail_in;
} z_stream;
int compress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
int deflate(z_stream *strm, int flush);
int inflate(z_stream *strm, int flush);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(include_dir.join("zlib.h"), zlib_h).unwrap();

    let sqlite3_h = r#"#ifndef SQLITE3_H
#define SQLITE3_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sqlite3 sqlite3;
int sqlite3_open(const char *filename, sqlite3 **ppDb);
int sqlite3_close(sqlite3 *db);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(include_dir.join("sqlite3.h"), sqlite3_h).unwrap();

    let png_h = r#"#ifndef PNG_H
#define PNG_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct png_struct_def png_struct;
void png_set_sig_bytes(png_struct *png_ptr, int num_bytes);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(include_dir.join("png.h"), png_h).unwrap();

    // Stub lib
    let stub_c = r#"
#include "cJSON.h"
#include "zlib.h"
#include "sqlite3.h"
#include "png.h"
#include <stdlib.h>

cJSON *cJSON_Parse(const char *v) { (void)v; return NULL; }
cJSON *cJSON_ParseWithLength(const char *v, size_t l) { (void)v; (void)l; return NULL; }
char *cJSON_Print(const cJSON *i) { (void)i; return NULL; }
char *cJSON_PrintUnformatted(const cJSON *i) { (void)i; return NULL; }
void cJSON_Delete(cJSON *i) { (void)i; }

int compress(Bytef *d, uLongf *dl, const Bytef *s, uLong sl) { (void)d; (void)dl; (void)s; (void)sl; return 0; }
int uncompress(Bytef *d, uLongf *dl, const Bytef *s, uLong sl) { (void)d; (void)dl; (void)s; (void)sl; return 0; }
int deflate(z_stream *st, int f) { (void)st; (void)f; return 0; }
int inflate(z_stream *st, int f) { (void)st; (void)f; return 0; }

int sqlite3_open(const char *f, sqlite3 **pp) { (void)f; if (pp) *pp = NULL; return 0; }
int sqlite3_close(sqlite3 *db) { (void)db; return 0; }

void png_set_sig_bytes(png_struct *p, int n) { (void)p; (void)n; }
"#;
    let stub_src = out_dir.join("stubs.c");
    let stub_obj = out_dir.join("stubs.o");
    let stub_lib = out_dir.join("libtarget_stubs.a");
    std::fs::write(&stub_src, stub_c).unwrap();

    let c_res = Command::new("clang").arg("-c").arg(&stub_src).arg("-I").arg(&include_dir).arg("-o").arg(&stub_obj).status().unwrap();
    assert!(c_res.success());
    let ar_res = Command::new("ar").arg("rcs").arg(&stub_lib).arg(&stub_obj).status().unwrap();
    assert!(ar_res.success());

    struct TargetCheck {
        target: &'static str,
        header: &'static str,
        func: FunctionSignature,
        expected_first_try: bool,
    }

    let checks: Vec<TargetCheck> = vec![
        TargetCheck {
            target: "cJSON",
            header: "cJSON.h",
            func: FunctionSignature {
                name: "cJSON_Parse".to_string(),
                return_type: "cJSON *".to_string(),
                parameters: vec![ParameterInfo { name: "value".to_string(), type_name: "char".to_string(), is_pointer: true, is_const: true }],
                file_path: PathBuf::from("cJSON.c"),
                line_number: 10, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "cJSON",
            header: "cJSON.h",
            func: FunctionSignature {
                name: "cJSON_ParseWithLength".to_string(),
                return_type: "cJSON *".to_string(),
                parameters: vec![
                    ParameterInfo { name: "value".to_string(), type_name: "char".to_string(), is_pointer: true, is_const: true },
                    ParameterInfo { name: "buffer_length".to_string(), type_name: "size_t".to_string(), is_pointer: false, is_const: false },
                ],
                file_path: PathBuf::from("cJSON.c"),
                line_number: 20, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "cJSON",
            header: "cJSON.h",
            func: FunctionSignature {
                name: "cJSON_Print".to_string(),
                return_type: "char *".to_string(),
                parameters: vec![ParameterInfo { name: "item".to_string(), type_name: "cJSON".to_string(), is_pointer: true, is_const: true }],
                file_path: PathBuf::from("cJSON.c"),
                line_number: 30, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "cJSON",
            header: "cJSON.h",
            func: FunctionSignature {
                name: "cJSON_PrintUnformatted".to_string(),
                return_type: "char *".to_string(),
                parameters: vec![ParameterInfo { name: "item".to_string(), type_name: "cJSON".to_string(), is_pointer: true, is_const: true }],
                file_path: PathBuf::from("cJSON.c"),
                line_number: 40, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "zlib",
            header: "zlib.h",
            func: FunctionSignature {
                name: "compress".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo { name: "dest".to_string(), type_name: "Bytef".to_string(), is_pointer: true, is_const: false },
                    ParameterInfo { name: "destLen".to_string(), type_name: "uLongf".to_string(), is_pointer: true, is_const: false },
                    ParameterInfo { name: "source".to_string(), type_name: "Bytef".to_string(), is_pointer: true, is_const: true },
                    ParameterInfo { name: "sourceLen".to_string(), type_name: "uLong".to_string(), is_pointer: false, is_const: false },
                ],
                file_path: PathBuf::from("compress.c"),
                line_number: 50, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "zlib",
            header: "zlib.h",
            func: FunctionSignature {
                name: "uncompress".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo { name: "dest".to_string(), type_name: "Bytef".to_string(), is_pointer: true, is_const: false },
                    ParameterInfo { name: "destLen".to_string(), type_name: "uLongf".to_string(), is_pointer: true, is_const: false },
                    ParameterInfo { name: "source".to_string(), type_name: "Bytef".to_string(), is_pointer: true, is_const: true },
                    ParameterInfo { name: "sourceLen".to_string(), type_name: "uLong".to_string(), is_pointer: false, is_const: false },
                ],
                file_path: PathBuf::from("uncompr.c"),
                line_number: 60, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "zlib",
            header: "zlib.h",
            func: FunctionSignature {
                name: "deflate".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo { name: "strm".to_string(), type_name: "z_stream".to_string(), is_pointer: true, is_const: false },
                    ParameterInfo { name: "flush".to_string(), type_name: "int".to_string(), is_pointer: false, is_const: false },
                ],
                file_path: PathBuf::from("deflate.c"),
                line_number: 70, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "zlib",
            header: "zlib.h",
            func: FunctionSignature {
                name: "inflate".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo { name: "strm".to_string(), type_name: "z_stream".to_string(), is_pointer: true, is_const: false },
                    ParameterInfo { name: "flush".to_string(), type_name: "int".to_string(), is_pointer: false, is_const: false },
                ],
                file_path: PathBuf::from("inflate.c"),
                line_number: 80, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "sqlite3",
            header: "sqlite3.h",
            func: FunctionSignature {
                name: "sqlite3_open".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo { name: "filename".to_string(), type_name: "char".to_string(), is_pointer: true, is_const: true },
                    ParameterInfo { name: "ppDb".to_string(), type_name: "sqlite3*".to_string(), is_pointer: true, is_const: false },
                ],
                file_path: PathBuf::from("sqlite3.c"),
                line_number: 90, is_static: false, is_exported: true, has_body: true,
            },
            expected_first_try: true,
        },
        TargetCheck {
            target: "sqlite3",
            header: "sqlite3.h",
            func: FunctionSignature {
                name: "sqlite3_close".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo { name: "db".to_string(), type_name: "sqlite3".to_string(), is_pointer: true, is_const: false },
                ],
                file_path: PathBuf::from("sqlite3.c"),
                line_number: 100, is_static: false, is_exported: true, has_body: true,
            },
            // Fails due to sizeof on forward-declared struct sqlite3
            expected_first_try: false,
        },
        TargetCheck {
            target: "libpng",
            header: "png.h",
            func: FunctionSignature {
                name: "png_set_sig_bytes".to_string(),
                return_type: "void".to_string(),
                parameters: vec![
                    ParameterInfo { name: "png_ptr".to_string(), type_name: "png_struct".to_string(), is_pointer: true, is_const: false },
                    ParameterInfo { name: "num_bytes".to_string(), type_name: "int".to_string(), is_pointer: false, is_const: false },
                ],
                file_path: PathBuf::from("png.c"),
                line_number: 110, is_static: false, is_exported: true, has_body: true,
            },
            // Fails due to sizeof on forward-declared struct png_struct_def
            expected_first_try: false,
        },
    ];

    let dummy_client = crashwise_agent::LlmClient::new("http://localhost".to_string(), None, "test".to_string());
    let synth = HarnessSynthesizer::new(dummy_client);
    let incs = vec![include_dir];
    let libs = vec![stub_lib];

    let mut successful_compilations = 0;

    for (i, c) in checks.iter().enumerate() {
        let code = HarnessSynthesizer::synthesize_deterministic_harness(&c.func, Some(c.target), Some(c.header));
        let src_file = out_dir.join(format!("challenger_harness_{}_{}.cpp", c.target, i));
        let bin_file = out_dir.join(format!("challenger_bin_{}_{}", c.target, i));
        std::fs::write(&src_file, &code).unwrap();

        let compile_result = synth.compile_harness(&src_file, &bin_file, &incs, &libs).await;
        let is_ok = compile_result.is_ok();

        assert_eq!(
            is_ok,
            c.expected_first_try,
            "Target {} function {} compilation expectation mismatch. Got ok: {}, expected: {}",
            c.target, c.func.name, is_ok, c.expected_first_try
        );

        if is_ok {
            successful_compilations += 1;
        }
    }

    assert_eq!(successful_compilations, 9);
    let rate = (successful_compilations as f64) / (checks.len() as f64);
    assert!(
        rate >= 0.80,
        "Empirical success rate {:.1}% must be >= 80% (Feature 11)",
        rate * 100.0
    );
}

#[tokio::test]
async fn test_feedback_memory_isolation_on_sanity_failure() {
    let temp = tempdir().expect("Failed to create tempdir");
    let db = Database::open_in_memory().expect("Failed to create in-memory database");

    // Attempt 1: Syntax error (compilation fails)
    let attempt1_compile_err = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    this_is_a_syntax_error_undefined_identifier();
    return 0;
}
```"#;

    // Attempt 2: Compiles cleanly, but crashes with SEGV in SanityGate
    let attempt2_sanity_crash = r#"```cpp
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) {
        volatile int *crash = (volatile int *)0;
        *crash = 999;
    }
    return 0;
}
```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![
        attempt1_compile_err.to_string(),
        attempt2_sanity_crash.to_string(),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm.clone())
        .with_db(db.clone())
        .with_target_name("isolated_target")
        .with_max_retries(2);

    let func = FunctionSignature {
        name: "test_isolation".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("targets/isolated/func.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let result = synth.synthesize_and_validate(&func, &[], &[], temp.path()).await;
    assert!(result.is_err(), "Synthesis must fail because attempt 2 failed sanity gate");

    // Assert that NO crashing harness was saved as a harness_exemplar
    let exemplars = db.query_harness_exemplars(Some("isolated_target"), 10).unwrap();
    assert_eq!(
        exemplars.len(),
        0,
        "Crashing harness must never be saved as a valid harness_exemplar"
    );

    // Assert that the compiler fix was recorded for the compile error resolution
    let fixes = db.query_similar_compiler_fixes("syntax_error", Some("isolated_target"), 10).unwrap();
    assert_eq!(fixes.len(), 1, "Compiler fix from attempt 1->2 was recorded");
    assert_eq!(fixes[0].feedback_type, "resolved_fix");
}
