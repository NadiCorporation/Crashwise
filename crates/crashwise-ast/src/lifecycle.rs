use crate::types::FunctionSignature;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulSequence {
    pub context_type: String,
    pub init_func: Option<FunctionSignature>,
    pub config_funcs: Vec<FunctionSignature>,
    pub process_funcs: Vec<FunctionSignature>,
    pub cleanup_func: Option<FunctionSignature>,
}

pub struct LifecycleMiner;

impl LifecycleMiner {
    pub fn mine_sequences(functions: &[FunctionSignature]) -> Vec<StatefulSequence> {
        let mut sequences = Vec::new();

        // Group functions by naming patterns and prefix (e.g. png_create_*, png_set_*, png_read_*, png_destroy_*)
        let mut prefix_groups: std::collections::HashMap<String, Vec<FunctionSignature>> = std::collections::HashMap::new();

        for func in functions {
            let parts: Vec<&str> = func.name.split('_').collect();
            if parts.len() >= 2 {
                let prefix = parts[0].to_string();
                prefix_groups.entry(prefix).or_default().push(func.clone());
            }
        }

        for (prefix, funcs) in prefix_groups {
            let mut init_func = None;
            let mut cleanup_func = None;
            let mut config_funcs = Vec::new();
            let mut process_funcs = Vec::new();

            for f in funcs {
                let lower = f.name.to_lowercase();
                if lower.contains("init")
                    || lower.contains("create")
                    || lower.contains("open")
                    || lower.contains("alloc")
                    || lower.contains("new")
                {
                    if init_func.is_none() {
                        init_func = Some(f);
                    }
                } else if lower.contains("free")
                    || lower.contains("destroy")
                    || lower.contains("close")
                    || lower.contains("cleanup")
                    || lower.contains("delete")
                {
                    if cleanup_func.is_none() {
                        cleanup_func = Some(f);
                    }
                } else if lower.contains("set")
                    || lower.contains("config")
                    || lower.contains("enable")
                    || lower.contains("option")
                {
                    config_funcs.push(f);
                } else if lower.contains("parse")
                    || lower.contains("read")
                    || lower.contains("process")
                    || lower.contains("decode")
                    || lower.contains("handle")
                {
                    process_funcs.push(f);
                }
            }

            if init_func.is_some() || !process_funcs.is_empty() {
                sequences.push(StatefulSequence {
                    context_type: format!("{}_context_t", prefix),
                    init_func,
                    config_funcs,
                    process_funcs,
                    cleanup_func,
                });
            }
        }

        sequences
    }
}
