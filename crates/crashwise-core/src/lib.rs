pub mod config;
pub mod db;
pub mod error;
pub mod models;

pub use config::CrashwiseConfig;
pub use db::Database;
pub use error::{CrashwiseError, Result};
pub use models::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_persistence() {
        let db = Database::open_in_memory().unwrap();

        let target = CampaignTarget {
            repo_url: "https://github.com/madler/zlib".to_string(),
            name: "zlib".to_string(),
            subdir: None,
            clone_depth: 1,
            commit_hash: None,
        };

        let campaign = Campaign::new(target, FuzzerEngine::Libfuzzer, 300, 3);
        db.insert_campaign(&campaign).unwrap();

        let list = db.list_campaigns().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].target.name, "zlib");
        assert_eq!(list[0].status, CampaignStatus::Pending);

        db.update_campaign_status(campaign.id, CampaignStatus::Running).unwrap();
        let updated = db.list_campaigns().unwrap();
        assert_eq!(updated[0].status, CampaignStatus::Running);
    }
}
