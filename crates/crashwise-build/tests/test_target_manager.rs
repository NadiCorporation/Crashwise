use crashwise_build::builder::TargetBuilder;
use crashwise_build::detector::{detect_build_system, detect_single_file_target, BuildSystemType};
use crashwise_build::target_manager::TargetManager;
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn test_target_spec_registry() {
    let targets = TargetManager::supported_targets();
    assert_eq!(targets.len(), 4);

    let names: Vec<String> = targets.iter().map(|t| t.name.clone()).collect();
    assert!(names.contains(&"cjson".to_string()));
    assert!(names.contains(&"zlib".to_string()));
    assert!(names.contains(&"libpng".to_string()));
    assert!(names.contains(&"sqlite3".to_string()));

    let cjson = TargetManager::get_spec("cjson").expect("cjson spec missing");
    assert_eq!(cjson.cve_id, "CVE-2019-1010239");
    assert_eq!(cjson.cwe_id, "CWE-122");
    assert_eq!(cjson.cvss_score, 8.8);
    assert_eq!(cjson.entrypoint, "cJSON_ParseWithLength");
    assert_eq!(cjson.header_file, "cJSON.h");

    let zlib = TargetManager::get_spec("zlib").expect("zlib spec missing");
    assert_eq!(zlib.cve_id, "CVE-2022-37434");
    assert_eq!(zlib.entrypoint, "inflateGetHeader");

    let libpng = TargetManager::get_spec("libpng").expect("libpng spec missing");
    assert_eq!(libpng.cve_id, "CVE-2019-7317");
    assert_eq!(libpng.entrypoint, "png_image_free");

    let sqlite3 = TargetManager::get_spec("sqlite3").expect("sqlite3 spec missing");
    assert_eq!(sqlite3.cve_id, "CVE-2022-35737");
    assert_eq!(sqlite3.entrypoint, "sqlite3_str_vappendf");
    assert_eq!(sqlite3.build_system, "single_file");
}

#[tokio::test]
async fn test_target_provisioning_offline_cjson() {
    let temp = tempdir().unwrap();
    let mgr = TargetManager::new(temp.path().to_path_buf());

    let target_dir = mgr.provision("cjson", true).await.expect("Provisioning cjson failed");
    assert!(target_dir.exists());
    assert!(target_dir.join("cJSON.h").exists());
    assert!(target_dir.join("cJSON.c").exists());
    assert!(target_dir.join("CMakeLists.txt").exists());
    assert!(target_dir.join("seed.bin").exists());
    assert!(target_dir.join("test.c").exists());

    let bs = detect_build_system(&target_dir).expect("CMakeLists.txt not detected");
    assert_eq!(bs.build_type, BuildSystemType::CMake);

    let builder = TargetBuilder::new(temp.path().to_path_buf());
    let output = builder.build_cmake(&target_dir).await.expect("cjson build failed");
    assert!(!output.static_libs.is_empty());
    assert!(output.static_libs[0].exists());
    assert!(output.include_dirs.contains(&target_dir));
}

#[tokio::test]
async fn test_target_provisioning_offline_zlib_generated_headers() {
    let temp = tempdir().unwrap();
    let mgr = TargetManager::new(temp.path().to_path_buf());

    let target_dir = mgr.provision("zlib", true).await.expect("Provisioning zlib failed");
    assert!(target_dir.join("zlib.h").exists());
    assert!(target_dir.join("CMakeLists.txt").exists());

    let builder = TargetBuilder::new(temp.path().to_path_buf());
    let output = builder.build_cmake(&target_dir).await.expect("zlib build failed");
    assert!(!output.static_libs.is_empty());

    let build_dir = target_dir.join("build-crashwise");
    assert!(build_dir.join("zconf.h").exists(), "zconf.h should be generated in build directory");
    assert!(
        output.include_dirs.contains(&build_dir),
        "build_dir containing zconf.h must be in include_dirs"
    );
}

#[tokio::test]
async fn test_target_provisioning_offline_libpng_generated_headers() {
    let temp = tempdir().unwrap();
    let mgr = TargetManager::new(temp.path().to_path_buf());

    let target_dir = mgr.provision("libpng", true).await.expect("Provisioning libpng failed");
    assert!(target_dir.join("png.h").exists());
    assert!(target_dir.join("CMakeLists.txt").exists());

    let builder = TargetBuilder::new(temp.path().to_path_buf());
    let output = builder.build_cmake(&target_dir).await.expect("libpng build failed");
    assert!(!output.static_libs.is_empty());

    let build_dir = target_dir.join("build-crashwise");
    assert!(build_dir.join("pnglibconf.h").exists(), "pnglibconf.h should be generated in build directory");
    assert!(
        output.include_dirs.contains(&build_dir),
        "build_dir containing pnglibconf.h must be in include_dirs"
    );
}

#[tokio::test]
async fn test_target_provisioning_offline_sqlite3_single_file() {
    let temp = tempdir().unwrap();
    let mgr = TargetManager::new(temp.path().to_path_buf());

    let target_dir = mgr.provision("sqlite3", true).await.expect("Provisioning sqlite3 failed");
    assert!(target_dir.join("sqlite3.h").exists());
    assert!(target_dir.join("sqlite3.c").exists());

    // Preserved contract: detect_build_system should return None for bare amalgamation directory
    assert!(detect_build_system(&target_dir).is_none());

    // detect_single_file_target correctly identifies sqlite3.c
    let single_file = detect_single_file_target(&target_dir).expect("sqlite3.c not detected");
    assert_eq!(single_file, target_dir.join("sqlite3.c"));

    let builder = TargetBuilder::new(temp.path().to_path_buf());
    let output = builder.build_auto(&target_dir).await.expect("sqlite3 build_auto failed");
    assert_eq!(output.static_libs.len(), 1);
    assert!(output.static_libs[0].exists());
    assert!(output.static_libs[0].file_name().unwrap().to_str().unwrap().contains("sqlite3"));
}

#[tokio::test]
async fn test_generated_header_discovery_skips_cmakefiles() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("mock_target");
    let build_dir = target_dir.join("build-crashwise");
    let cmake_files = build_dir.join("CMakeFiles").join("CheckTypeSize");
    let valid_inc = build_dir.join("generated_include");

    fs::create_dir_all(&cmake_files).unwrap();
    fs::create_dir_all(&valid_inc).unwrap();
    fs::write(cmake_files.join("internal.h"), "#define INTERNAL\n").unwrap();
    fs::write(valid_inc.join("exported.h"), "#define EXPORTED\n").unwrap();

    let incs = TargetBuilder::collect_include_dirs(&target_dir, Some(&build_dir), None);
    assert!(incs.contains(&valid_inc));
    assert!(!incs.contains(&cmake_files));
}

#[tokio::test]
async fn test_compile_commands_include_extraction() {
    let temp = tempdir().unwrap();
    let inc1 = temp.path().join("include_one");
    let inc2 = temp.path().join("include_two");
    fs::create_dir_all(&inc1).unwrap();
    fs::create_dir_all(&inc2).unwrap();

    let cc_path = temp.path().join("compile_commands.json");
    let json_content = format!(
        r#"[
            {{
                "directory": "{}",
                "command": "clang -I{} -isystem {} -c file.c",
                "file": "file.c"
            }}
        ]"#,
        temp.path().display(),
        inc1.display(),
        inc2.display()
    );
    fs::write(&cc_path, json_content).unwrap();

    let extracted = TargetBuilder::extract_compile_commands_includes(&cc_path);
    assert_eq!(extracted.len(), 2);
    assert!(extracted.contains(&inc1));
    assert!(extracted.contains(&inc2));
}

#[tokio::test]
async fn test_unknown_target_provisioning_error() {
    let temp = tempdir().unwrap();
    let mgr = TargetManager::new(temp.path().to_path_buf());

    let result = mgr.provision("invalid_target_123", true).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Unsupported target"));
}
