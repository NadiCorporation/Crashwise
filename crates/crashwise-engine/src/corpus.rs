use std::path::{Path, PathBuf};
use tokio::fs;

pub struct CorpusManager {
    pub corpus_dir: PathBuf,
}

impl CorpusManager {
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        Self {
            corpus_dir: dir.as_ref().to_path_buf(),
        }
    }

    pub async fn ensure_seed_corpus(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.corpus_dir).await?;

        // If empty, generate standard starter seeds
        let mut entries = fs::read_dir(&self.corpus_dir).await?;
        if entries.next_entry().await?.is_none() {
            let seeds = [
                b"CRASHWISE_SEED_EMPTY".to_vec(),
                b"\x00\x00\x00\x00\xff\xff\xff\xff".to_vec(),
                b"{\"test\": 123}".to_vec(),
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec(),
            ];

            for (i, seed) in seeds.iter().enumerate() {
                let seed_file = self.corpus_dir.join(format!("seed_{:03}.bin", i));
                fs::write(seed_file, seed).await?;
            }
        }
        Ok(())
    }

    pub async fn count_seeds(&self) -> std::io::Result<usize> {
        let mut count = 0;
        if self.corpus_dir.exists() {
            let mut entries = fs::read_dir(&self.corpus_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                if entry.file_type().await?.is_file() {
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}
