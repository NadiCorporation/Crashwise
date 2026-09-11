use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    pub name: String,
    pub type_name: String,
    pub is_pointer: bool,
    pub is_const: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<ParameterInfo>,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub is_static: bool,
    pub is_exported: bool,
    pub has_body: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructFieldInfo {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructInfo {
    pub name: String,
    pub fields: Vec<StructFieldInfo>,
    pub file_path: PathBuf,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousSink {
    pub function_name: String,
    pub sink_type: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub caller: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAstProfile {
    pub functions: Vec<FunctionSignature>,
    pub structs: Vec<StructInfo>,
    pub dangerous_sinks: Vec<DangerousSink>,
    pub public_headers: Vec<PathBuf>,
}
