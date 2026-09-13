use crashwise_engine::CorpusManager;
use tempfile::TempDir;

#[tokio::test]
async fn test_corpus_ensure_seeds_and_count() {
    let temp = TempDir::new().unwrap();
    let manager = CorpusManager::new(temp.path().join("corpus"));

    assert_eq!(manager.count_seeds().await.unwrap(), 0);

    manager.ensure_seed_corpus().await.unwrap();
    let count = manager.count_seeds().await.unwrap();
    assert_eq!(count, 4, "Expected 4 default starter seeds");

    // Calling ensure_seed_corpus again should not overwrite or duplicate
    manager.ensure_seed_corpus().await.unwrap();
    assert_eq!(manager.count_seeds().await.unwrap(), 4);
}

#[test]
fn test_corpus_sync_methods() {
    let temp = TempDir::new().unwrap();
    let manager = CorpusManager::new(temp.path().join("sync_corpus"));

    let saved = manager.save_seed_sync("seed_1.bin", b"TEST_SEED_SYNC").unwrap();
    assert!(saved.exists());

    let loaded = manager.load_seeds_sync().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0], b"TEST_SEED_SYNC");
}
