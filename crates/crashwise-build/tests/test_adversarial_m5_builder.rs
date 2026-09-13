use crashwise_build::builder::TargetBuilder;
use crashwise_build::detector::{detect_build_system, detect_single_file_target};
use crashwise_build::target_manager::TargetManager;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::tempdir;

#[tokio::test]
async fn test_offline_provisioning_all_four_targets_cve_reproduction() {
    let temp = tempdir().unwrap();
    let mgr = TargetManager::new(temp.path().to_path_buf());

    // 1. Provision all 4 targets in offline mode
    let targets = mgr.provision_all(true).await.expect("Failed to provision all targets offline");
    assert_eq!(targets.len(), 4);

    for (spec, target_dir) in &targets {
        assert!(target_dir.exists(), "Target directory must exist for {}", spec.name);
        assert!(target_dir.join(&spec.header_file).exists(), "Header {} missing for {}", spec.header_file, spec.name);
        assert!(target_dir.join("seed.bin").exists(), "seed.bin missing for {}", spec.name);
        assert!(target_dir.join("test.c").exists(), "test.c missing for {}", spec.name);
    }

    // 2. Adversarially verify cJSON CVE-2019-1010239 vulnerability triggers ASan
    let cjson_dir = temp.path().join("cjson");
    let cjson_poc_src = cjson_dir.join("adv_poc.c");
    let cjson_poc_bin = cjson_dir.join("adv_poc_bin");
    fs::write(&cjson_poc_src, r#"
        #include "cJSON.h"
        #include <stdio.h>
        #include <stdlib.h>
        int main(void) {
            const char unclosed[] = "\"unclosed string without end quote";
            cJSON *j = cJSON_ParseWithLength(unclosed, sizeof(unclosed) - 1);
            if (j) cJSON_Delete(j);
            return 0;
        }
    "#).unwrap();

    let status = Command::new("clang")
        .args(["-fsanitize=address", "-g", "-O0"])
        .arg("-I").arg(&cjson_dir)
        .arg(cjson_dir.join("cJSON.c"))
        .arg(&cjson_poc_src)
        .arg("-o").arg(&cjson_poc_bin)
        .output()
        .expect("Failed to compile cJSON ASan PoC");
    assert!(status.status.success(), "cJSON ASan compilation failed");

    let poc_out = Command::new(&cjson_poc_bin)
        .env("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0")
        .output()
        .expect("Failed to run cJSON PoC");
    let stderr = String::from_utf8_lossy(&poc_out.stderr);
    assert!(!poc_out.status.success(), "cJSON PoC should crash");
    assert!(stderr.contains("AddressSanitizer: heap-buffer-overflow"), "Expected heap-buffer-overflow in cJSON, got: {}", stderr);

    // 3. Adversarially verify zlib CVE-2022-37434 vulnerability triggers ASan
    let zlib_dir = temp.path().join("zlib");
    let zlib_poc_src = zlib_dir.join("adv_poc.c");
    let zlib_poc_bin = zlib_dir.join("adv_poc_bin");
    fs::write(&zlib_poc_src, r#"
        #include "zlib.h"
        #include <stdlib.h>
        #include <string.h>
        int main(void) {
            struct gz_header head;
            head.extra_max = 8;
            head.extra = (unsigned char*)malloc(head.extra_max);
            char malicious[32];
            memset(malicious, 0x41, sizeof(malicious));
            int res = inflateGetHeader(&head, malicious, sizeof(malicious));
            free(head.extra);
            return res;
        }
    "#).unwrap();

    let status = Command::new("clang")
        .args(["-fsanitize=address", "-g", "-O1"])
        .arg("-I").arg(&zlib_dir)
        .arg(zlib_dir.join("zlib.c"))
        .arg(&zlib_poc_src)
        .arg("-o").arg(&zlib_poc_bin)
        .status()
        .expect("Failed to compile zlib ASan PoC");
    assert!(status.success(), "zlib ASan compilation failed");

    let poc_out = Command::new(&zlib_poc_bin).output().expect("Failed to run zlib PoC");
    let stderr = String::from_utf8_lossy(&poc_out.stderr);
    assert!(!poc_out.status.success(), "zlib PoC should crash");
    assert!(stderr.contains("AddressSanitizer: heap-buffer-overflow"), "Expected heap-buffer-overflow in zlib, got: {}", stderr);

    // 4. Adversarially verify libpng CVE-2019-7317 vulnerability triggers ASan UAF / double-free
    let libpng_dir = temp.path().join("libpng");
    let libpng_poc_src = libpng_dir.join("adv_poc.c");
    let libpng_poc_bin = libpng_dir.join("adv_poc_bin");
    fs::write(&libpng_poc_src, r#"
        #include "png.h"
        #include <stdlib.h>
        int main(void) {
            struct png_image img;
            img.opaque = malloc(16);
            png_image_free(&img);
            png_image_free(&img);
            return 0;
        }
    "#).unwrap();

    let status = Command::new("clang")
        .args(["-fsanitize=address", "-g", "-O1"])
        .arg("-I").arg(&libpng_dir)
        .arg(libpng_dir.join("png.c"))
        .arg(&libpng_poc_src)
        .arg("-o").arg(&libpng_poc_bin)
        .status()
        .expect("Failed to compile libpng ASan PoC");
    assert!(status.success(), "libpng ASan compilation failed");

    let poc_out = Command::new(&libpng_poc_bin).output().expect("Failed to run libpng PoC");
    let stderr = String::from_utf8_lossy(&poc_out.stderr);
    assert!(!poc_out.status.success(), "libpng PoC should crash");
    assert!(stderr.contains("AddressSanitizer: attempting double-free") || stderr.contains("AddressSanitizer: heap-use-after-free"), "Expected double-free or UAF in libpng, got: {}", stderr);

    // 5. Adversarially verify sqlite3 CVE-2022-35737 vulnerability triggers ASan
    let sqlite3_dir = temp.path().join("sqlite3");
    let sqlite3_poc_src = sqlite3_dir.join("adv_poc.c");
    let sqlite3_poc_bin = sqlite3_dir.join("adv_poc_bin");
    fs::write(&sqlite3_poc_src, r#"
        #include "sqlite3.h"
        #include <stdlib.h>
        int main(void) {
            char *buf = (char*)malloc(16);
            sqlite3_str_vappendf(buf, 16, -12);
            free(buf);
            return 0;
        }
    "#).unwrap();

    let status = Command::new("clang")
        .args(["-fsanitize=address", "-g", "-O1"])
        .arg("-I").arg(&sqlite3_dir)
        .arg(sqlite3_dir.join("sqlite3.c"))
        .arg(&sqlite3_poc_src)
        .arg("-o").arg(&sqlite3_poc_bin)
        .status()
        .expect("Failed to compile sqlite3 ASan PoC");
    assert!(status.success(), "sqlite3 ASan compilation failed");

    let poc_out = Command::new(&sqlite3_poc_bin).output().expect("Failed to run sqlite3 PoC");
    let stderr = String::from_utf8_lossy(&poc_out.stderr);
    assert!(!poc_out.status.success(), "sqlite3 PoC should crash");
    assert!(stderr.contains("AddressSanitizer: heap-buffer-overflow"), "Expected heap-buffer-overflow in sqlite3, got: {}", stderr);
}

#[tokio::test]
async fn test_target_manager_corrupt_cache_and_permission_errors() {
    let temp = tempdir().unwrap();

    // Case 1: Cache path points to a file, so create_dir_all fails
    let file_cache = temp.path().join("cache_is_a_file");
    fs::write(&file_cache, "blocking file").unwrap();

    let mgr = TargetManager::new(file_cache);
    let res = mgr.provision("cjson", true).await;
    assert!(res.is_err(), "Provisioning into a file path cache should return Err");

    // Case 2: Read-only directory causes permission error when creating target directory
    let ro_cache = temp.path().join("readonly_cache");
    fs::create_dir_all(&ro_cache).unwrap();
    let mut perms = fs::metadata(&ro_cache).unwrap().permissions();
    perms.set_mode(0o444); // Read-only
    let _ = fs::set_permissions(&ro_cache, perms.clone());

    let mgr_ro = TargetManager::new(ro_cache.clone());
    let res_ro = mgr_ro.provision("zlib", true).await;
    assert!(res_ro.is_err(), "Provisioning into read-only cache must fail with Err");

    // Restore permissions for cleanup
    perms.set_mode(0o755);
    let _ = fs::set_permissions(&ro_cache, perms);

    // Case 3: Target dir exists with corrupted contents (missing header), should re-provision
    let valid_cache = temp.path().join("valid_cache");
    let corrupt_target = valid_cache.join("cjson");
    fs::create_dir_all(&corrupt_target).unwrap();
    fs::write(corrupt_target.join("garbage.txt"), "no headers here").unwrap();

    let mgr_corrupt = TargetManager::new(valid_cache);
    let res_reprov = mgr_corrupt.provision("cjson", true).await;
    assert!(res_reprov.is_ok(), "TargetManager should successfully re-provision if header is missing");
    assert!(corrupt_target.join("cJSON.h").exists(), "Header must be restored");
}

#[tokio::test]
async fn test_target_manager_invalid_target_inputs() {
    let temp = tempdir().unwrap();
    let mgr = TargetManager::new(temp.path().to_path_buf());

    let invalid_names = vec![
        "",
        "   ",
        "cjson_plus_plus",
        "SQLITE4",
        "../../etc/passwd",
        "\0nullbyte",
        "openssl",
    ];

    for name in invalid_names {
        let res = mgr.provision(name, true).await;
        assert!(res.is_err(), "Expected error for invalid target '{}'", name);
    }
}

#[tokio::test]
async fn test_target_builder_nested_generated_headers_and_cmake_git_filtering() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("complex_target");
    let build_dir = target_dir.join("build-crashwise");

    // Construct deeply nested directories
    let deeply_nested = build_dir.join("deep").join("nested").join("include");
    let cmake_nested = build_dir.join("CMakeFiles").join("CheckType").join("nested");
    let git_nested = build_dir.join(".git").join("hooks");
    let src_nested = target_dir.join("src").join("internal");

    fs::create_dir_all(&deeply_nested).unwrap();
    fs::create_dir_all(&cmake_nested).unwrap();
    fs::create_dir_all(&git_nested).unwrap();
    fs::create_dir_all(&src_nested).unwrap();

    fs::write(deeply_nested.join("deep_generated.h"), "#define DEEP 1\n").unwrap();
    fs::write(cmake_nested.join("cmake_probe.h"), "#define CMAKE_INTERNAL\n").unwrap();
    fs::write(git_nested.join("git_header.h"), "#define GIT_INTERNAL\n").unwrap();
    fs::write(src_nested.join("internal.h"), "#define INTERNAL\n").unwrap();

    let incs = TargetBuilder::collect_include_dirs(&target_dir, Some(&build_dir), None);

    // Assert valid directories are present
    assert!(incs.contains(&deeply_nested), "Deeply nested include dir should be discovered");
    assert!(incs.contains(&src_nested), "Nested src include dir should be discovered");

    // Assert CMakeFiles and .git are strictly excluded
    for inc in &incs {
        let inc_str = inc.to_string_lossy();
        assert!(!inc_str.contains("CMakeFiles"), "Found CMakeFiles in include dirs: {}", inc_str);
        assert!(!inc_str.contains(".git"), "Found .git in include dirs: {}", inc_str);
    }
}

#[tokio::test]
async fn test_target_builder_compile_commands_malformed_resilience() {
    let temp = tempdir().unwrap();

    // Case 1: Non-existent compile_commands.json
    let non_existent = temp.path().join("missing.json");
    let incs = TargetBuilder::extract_compile_commands_includes(&non_existent);
    assert!(incs.is_empty());

    // Case 2: Corrupted non-JSON file
    let corrupt_json = temp.path().join("corrupted.json");
    fs::write(&corrupt_json, "NOT JSON AT ALL {{{").unwrap();
    let incs2 = TargetBuilder::extract_compile_commands_includes(&corrupt_json);
    assert!(incs2.is_empty());

    // Case 3: JSON object instead of array
    let obj_json = temp.path().join("obj.json");
    fs::write(&obj_json, r#"{"error": "not an array"}"#).unwrap();
    let incs3 = TargetBuilder::extract_compile_commands_includes(&obj_json);
    assert!(incs3.is_empty());

    // Case 4: Nonexistent -I paths filtered out
    let valid_json = temp.path().join("valid_syntax_bad_paths.json");
    fs::write(&valid_json, r#"[
        {
            "directory": "/tmp",
            "command": "clang -I/nonexistent/directory/xyz987 -isystem /another/fake/dir -c foo.c",
            "file": "foo.c"
        }
    ]"#).unwrap();
    let incs4 = TargetBuilder::extract_compile_commands_includes(&valid_json);
    assert!(incs4.is_empty(), "Non-existent paths in compile_commands must be omitted");
}

#[tokio::test]
async fn test_target_builder_single_file_compilation_error_propagation() {
    let temp = tempdir().unwrap();
    let builder = TargetBuilder::new(temp.path().to_path_buf());

    // Case 1: Syntax error in single C file
    let syntax_err_file = temp.path().join("syntax_error.c");
    fs::write(&syntax_err_file, r#"
        int foo( { // syntax error
            return 1
    "#).unwrap();

    let res = builder.build_single_file(&syntax_err_file, &[]).await;
    assert!(res.is_err(), "build_single_file must fail cleanly on syntax error");
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("Compilation of") || err_str.contains("failed"), "Error message: {}", err_str);

    // Case 2: Missing include file in single C file
    let missing_inc_file = temp.path().join("missing_inc.c");
    fs::write(&missing_inc_file, r#"
        #include "completely_nonexistent_header_12345.h"
        int main(void) { return 0; }
    "#).unwrap();

    let res2 = builder.build_single_file(&missing_inc_file, &[]).await;
    assert!(res2.is_err(), "build_single_file must fail cleanly on missing include");

    // Case 3: Nonexistent source file
    let nonexistent_file = temp.path().join("does_not_exist.c");
    let res3 = builder.build_single_file(&nonexistent_file, &[]).await;
    assert!(res3.is_err(), "build_single_file must fail cleanly on missing source file");
}

#[tokio::test]
async fn test_target_builder_build_auto_fallback_and_rejection() {
    let temp = tempdir().unwrap();
    let builder = TargetBuilder::new(temp.path().to_path_buf());

    // Empty directory: no build system, no single C file
    let empty_dir = temp.path().join("empty_dir");
    fs::create_dir_all(&empty_dir).unwrap();

    let res = builder.build_auto(&empty_dir).await;
    assert!(res.is_err(), "build_auto on empty directory must return Err");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("No supported build system or single-file C target detected"));

    // Directory with only txt files
    fs::write(empty_dir.join("readme.txt"), "hello").unwrap();
    assert!(detect_build_system(&empty_dir).is_none());
    assert!(detect_single_file_target(&empty_dir).is_none());
    assert!(builder.build_auto(&empty_dir).await.is_err());
}
