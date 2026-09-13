use crashwise_triage::patch_applier::PatchApplier;
use crashwise_triage::patch_synth::PatchCandidate;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_patch_applier_apply_and_explicit_rollback() {
    let temp = tempdir().unwrap();
    let src_file = temp.path().join("module.c");
    let original = "int func(void) {\n    return 1;\n}\n";
    fs::write(&src_file, original).unwrap();

    let diff = r#"--- a/module.c
+++ b/module.c
@@ -1,3 +1,4 @@
 int func(void) {
+    /* patched */
     return 1;
 }
"#;

    let mut guard = PatchApplier::apply(&src_file, diff).expect("Patch apply failed");
    let patched = fs::read_to_string(&src_file).unwrap();
    assert!(patched.contains("/* patched */"));
    assert!(guard.backup_path().exists());

    guard.rollback().expect("Rollback failed");
    let restored = fs::read_to_string(&src_file).unwrap();
    assert_eq!(restored, original);
    assert!(!guard.backup_path().exists());
}

#[test]
fn test_patch_applier_commit_keeps_patch_and_removes_backup() {
    let temp = tempdir().unwrap();
    let src_file = temp.path().join("source.c");
    let original = "void run(void) {}\n";
    fs::write(&src_file, original).unwrap();

    let diff = r#"--- a/source.c
+++ b/source.c
@@ -1,1 +1,2 @@
+/* guard check */
 void run(void) {}
"#;

    let mut guard = PatchApplier::apply(&src_file, diff).expect("Failed to apply patch");
    let backup_path = guard.backup_path().to_path_buf();
    assert!(backup_path.exists());

    guard.commit();
    assert!(!backup_path.exists());
    let current_content = fs::read_to_string(&src_file).unwrap();
    assert!(current_content.contains("/* guard check */"));
}

#[test]
fn test_patch_applier_raii_drop_rollback() {
    let temp = tempdir().unwrap();
    let src_file = temp.path().join("core.c");
    let original = "char* get_version() { return \"1.0\"; }\n";
    fs::write(&src_file, original).unwrap();

    let diff = r#"--- a/core.c
+++ b/core.c
@@ -1,1 +1,2 @@
+/* temporary test */
 char* get_version() { return "1.0"; }
"#;

    {
        let _guard = PatchApplier::apply(&src_file, diff).unwrap();
        let modified = fs::read_to_string(&src_file).unwrap();
        assert!(modified.contains("/* temporary test */"));
    } // _guard drops here

    let reverted = fs::read_to_string(&src_file).unwrap();
    assert_eq!(reverted, original);
}

#[test]
fn test_patch_applier_resolve_file_in_dir() {
    let temp = tempdir().unwrap();
    let sub = temp.path().join("src");
    fs::create_dir_all(&sub).unwrap();
    let target = sub.join("algorithm.c");
    fs::write(&target, "int algo() { return 0; }\n").unwrap();

    let patch = PatchCandidate {
        file_path: "src/algorithm.c".to_string(),
        unified_diff: r#"--- a/src/algorithm.c
+++ b/src/algorithm.c
@@ -1,1 +1,2 @@
+/* algo guard */
 int algo() { return 0; }
"#
        .to_string(),
        explanation: "test patch".to_string(),
    };

    let mut guard = PatchApplier::apply_patch(temp.path(), &patch).expect("Failed to apply patch");
    let content = fs::read_to_string(&target).unwrap();
    assert!(content.contains("/* algo guard */"));

    guard.rollback().unwrap();
    let reverted = fs::read_to_string(&target).unwrap();
    assert_eq!(reverted, "int algo() { return 0; }\n");
}

#[test]
fn test_patch_applier_edge_cases() {
    // 1. Empty diff returns original content
    let orig = "line 1\nline 2\n";
    let res = PatchApplier::apply_diff_to_content(orig, "").unwrap();
    assert_eq!(res, orig);

    // 2. Corrupted hunk header ignored safely
    let bad_diff = "@@ corrupted header @@\n+added\n";
    let res2 = PatchApplier::apply_diff_to_content(orig, bad_diff).unwrap();
    assert_eq!(res2, orig);

    // 3. Out of bounds line number clamped
    let oob_diff = "@@ -9999,1 +9999,1 @@\n+extra_line\n";
    let res3 = PatchApplier::apply_diff_to_content(orig, oob_diff).unwrap();
    assert!(res3.contains("extra_line"));

    // 4. Missing file returns error
    let temp = tempdir().unwrap();
    let missing = temp.path().join("nonexistent.c");
    let err = PatchApplier::apply(&missing, "@@ -1,1 +1,1 @@\n");
    assert!(err.is_err());
}
