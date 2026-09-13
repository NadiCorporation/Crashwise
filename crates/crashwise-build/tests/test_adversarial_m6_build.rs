use crashwise_build::builder::TargetBuilder;
use crashwise_build::target_manager::TargetManager;
use crashwise_core::error::CrashwiseError;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[tokio::test]
async fn test_m6_network_fallback_and_offline_provisioning_resilience() {
    let temp = tempdir().expect("tempdir");
    let mgr = TargetManager::new(temp.path().to_path_buf());

    let target_names = ["cjson", "zlib", "libpng", "sqlite3"];

    for name in target_names {
        // Test provisioning with offline: true
        let offline_path = mgr.provision(name, true).await
            .unwrap_or_else(|e| panic!("Offline provisioning failed for {name}: {e}"));

        assert!(offline_path.exists());
        let spec = TargetManager::get_spec(name).expect("Spec must exist");
        assert!(offline_path.join(&spec.header_file).exists(), "Header {} must exist", spec.header_file);
        assert!(offline_path.join("seed.bin").exists(), "seed.bin must exist");
        assert!(offline_path.join("test.c").exists(), "test.c must exist");

        let seed_bytes = fs::read(offline_path.join("seed.bin")).expect("read seed");
        assert_eq!(seed_bytes, spec.seed_payload, "Seed payload must match spec");

        // Verify cache hit behavior: second provision returns immediately
        let cached_path = mgr.provision(name, true).await.expect("Cache hit provision failed");
        assert_eq!(cached_path, offline_path);
    }
}

#[tokio::test]
async fn test_m6_target_manager_malicious_and_invalid_inputs() {
    let temp = tempdir().expect("tempdir");
    let mgr = TargetManager::new(temp.path().to_path_buf());

    let invalid_names = [
        "",
        " ",
        "unknown_lib",
        "../../etc/passwd",
        "cjson; rm -rf /",
        "libpng\0injection",
        "OPENSSL",
    ];

    for bad in invalid_names {
        assert!(TargetManager::get_spec(bad).is_none(), "Bad name should not resolve spec: {:?}", bad);
        let res = mgr.provision(bad, true).await;
        match res {
            Err(CrashwiseError::BuildError(msg)) => {
                assert!(msg.contains("Unsupported target"), "Expected 'Unsupported target', got: {msg}");
            }
            other => panic!("Expected BuildError for input {:?}, got {:?}", bad, other),
        }
    }
}

#[tokio::test]
async fn test_m6_sqlite3_single_file_amalgamation_compilation() {
    let temp = tempdir().expect("tempdir");
    let mgr = TargetManager::new(temp.path().join("targets"));
    let target_dir = mgr.provision("sqlite3", true).await.expect("provision sqlite3");

    let source_file = target_dir.join("sqlite3.c");
    assert!(source_file.exists(), "sqlite3.c must exist");

    let workdir = temp.path().join("build_work");
    let builder = TargetBuilder::new(workdir).with_sanitizers(vec!["address".to_string()]);

    let build_out = builder.build_single_file(&source_file, std::slice::from_ref(&target_dir)).await
        .expect("Single file compilation of sqlite3.c failed");

    assert_eq!(build_out.static_libs.len(), 1);
    let lib = &build_out.static_libs[0];
    assert!(lib.exists(), "libsqlite3.a must exist at {}", lib.display());

    // Verify static library is a valid archive containing sqlite3.o
    let ar_output = Command::new("ar")
        .args(["-t", lib.to_str().unwrap()])
        .output()
        .expect("ar -t failed");
    assert!(ar_output.status.success());
    let listing = String::from_utf8_lossy(&ar_output.stdout);
    assert!(listing.contains("sqlite3.o"), "libsqlite3.a must contain sqlite3.o, got: {listing}");

    // Verify include directories contain target dir
    assert!(build_out.include_dirs.iter().any(|d| d == &target_dir));
}

#[tokio::test]
async fn test_m6_generated_header_harvesting_and_directory_filtering() {
    let temp = tempdir().expect("tempdir");
    let target_dir = temp.path().join("mock_target");
    let build_dir = target_dir.join("build-crashwise");

    // Setup source dirs
    fs::create_dir_all(target_dir.join("include")).unwrap();
    fs::create_dir_all(target_dir.join("src/nested")).unwrap();
    fs::write(target_dir.join("include/target.h"), "#define TARGET 1\n").unwrap();
    fs::write(target_dir.join("src/nested/internal.h"), "#define INTERNAL 1\n").unwrap();

    // Setup build dir with generated headers
    fs::create_dir_all(build_dir.join("generated/sub")).unwrap();
    fs::write(build_dir.join("generated/zconf.h"), "#define ZCONF 1\n").unwrap();
    fs::write(build_dir.join("generated/sub/types.inc"), "#define TYPES 1\n").unwrap();

    // Setup noisy build subdirectories that MUST be ignored
    fs::create_dir_all(build_dir.join("CMakeFiles/foo")).unwrap();
    fs::write(build_dir.join("CMakeFiles/foo/cmake.h"), "#define CMAKE 1\n").unwrap();

    fs::create_dir_all(build_dir.join(".git/hooks")).unwrap();
    fs::write(build_dir.join(".git/hooks/git.h"), "#define GIT 1\n").unwrap();

    let incs = TargetBuilder::collect_include_dirs(&target_dir, Some(&build_dir), None);

    // Assert harvested directories
    assert!(incs.iter().any(|d| d == &target_dir), "target_dir must be included");
    assert!(incs.iter().any(|d| d == &target_dir.join("include")), "include/ must be included");
    assert!(incs.iter().any(|d| d == &target_dir.join("src")), "src/ must be included");
    assert!(incs.iter().any(|d| d == &target_dir.join("src/nested")), "src/nested must be included");
    assert!(incs.iter().any(|d| d == &build_dir.join("generated")), "generated/ must be included");
    assert!(incs.iter().any(|d| d == &build_dir.join("generated/sub")), "generated/sub/ must be included");

    // Assert noise directories are strictly EXCLUDED
    for d in &incs {
        let s = d.to_string_lossy();
        assert!(!s.contains("CMakeFiles"), "CMakeFiles must never be harvested: {}", s);
        assert!(!s.contains(".git"), ".git must never be harvested: {}", s);
    }
}

#[test]
fn test_m6_compile_commands_malformed_and_edge_case_parsing() {
    let temp = tempdir().expect("tempdir");
    let valid_dir = temp.path().join("valid_include");
    let valid_sys_dir = temp.path().join("valid_sys_include");
    fs::create_dir_all(&valid_dir).unwrap();
    fs::create_dir_all(&valid_sys_dir).unwrap();

    // 1. Nonexistent file
    let missing_path = temp.path().join("nonexistent.json");
    let res = TargetBuilder::extract_compile_commands_includes(&missing_path);
    assert!(res.is_empty());

    // 2. Corrupt / invalid JSON
    let corrupt_path = temp.path().join("corrupt.json");
    fs::write(&corrupt_path, "{ this is not valid JSON ]").unwrap();
    let res_corrupt = TargetBuilder::extract_compile_commands_includes(&corrupt_path);
    assert!(res_corrupt.is_empty());

    // 3. Valid compile_commands.json with mixed formats, relative paths, and duplicates
    let cc_path = temp.path().join("compile_commands.json");
    let json_content = serde_json::json!([
        {
            "directory": temp.path().to_str().unwrap(),
            "command": format!("clang -c main.c -I{} -isystem {}", valid_dir.display(), valid_sys_dir.display()),
            "file": "main.c"
        },
        {
            "directory": temp.path().to_str().unwrap(),
            "arguments": [
                "clang",
                "-c",
                "-I",
                valid_dir.to_str().unwrap(), // duplicate
                "-I/nonexistent/directory/path/that/does/not/exist",
                "test.c"
            ],
            "file": "test.c"
        }
    ]);

    fs::write(&cc_path, json_content.to_string()).unwrap();

    let incs = TargetBuilder::extract_compile_commands_includes(&cc_path);
    assert_eq!(incs.len(), 2, "Must contain exactly valid_dir and valid_sys_dir (deduplicated)");
    assert!(incs.contains(&valid_dir));
    assert!(incs.contains(&valid_sys_dir));
}
