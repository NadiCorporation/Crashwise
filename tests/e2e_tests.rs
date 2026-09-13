//! CrashWise Comprehensive Opaque-Box E2E Test Suite
//!
//! Tiers 1-4 Verification:
//! - Tier 1: Feature Coverage (Features 1.1 through 1.11, >=5 tests/feature)
//! - Tier 2: Boundary & Corner Cases (Categories 2.1 through 2.7, >=5 tests/category)
//! - Tier 3: Cross-Feature Combinations (Pairwise pipelines)
//! - Tier 4: Real-World Application Scenarios (cJSON, zlib, libpng, sqlite3, concurrent)

mod test_helpers;
mod tier1_feature_coverage;
mod tier2_boundary_corner;
mod tier3_cross_feature;
mod tier4_real_world_scenarios;
mod tier5_whitebox_adversarial;
