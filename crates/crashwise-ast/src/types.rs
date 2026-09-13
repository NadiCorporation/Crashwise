use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub offset_bytes: usize,
    #[serde(default)]
    pub size_bytes: usize,
    #[serde(default)]
    pub align_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructInfo {
    pub name: String,
    pub fields: Vec<StructFieldInfo>,
    pub file_path: PathBuf,
    pub line_number: usize,
    #[serde(default)]
    pub total_size_bytes: usize,
    #[serde(default)]
    pub align_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeKind {
    Primitive {
        name: String,
        size_bytes: usize,
        align_bytes: usize,
    },
    Pointer {
        pointee: Box<TypeKind>,
        indirection: usize,
        is_const: bool,
    },
    StructRef {
        name: String,
    },
    UnionRef {
        name: String,
    },
    EnumRef {
        name: String,
        variants: Vec<(String, i64)>,
    },
    TypedefRef {
        name: String,
        target: Box<TypeKind>,
    },
    Array {
        element: Box<TypeKind>,
        len: Option<usize>,
    },
    FunctionPointer {
        return_type: Box<TypeKind>,
        parameters: Vec<ParameterInfo>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldLayout {
    pub name: String,
    pub type_kind: TypeKind,
    pub offset_bytes: usize,
    pub size_bytes: usize,
    pub align_bytes: usize,
    pub is_bitfield: bool,
    pub bit_width: Option<u32>,
    pub bit_offset: Option<u32>,
    pub nested_struct: Option<Box<StructLayout>>,
    pub nested_union: Option<Box<UnionLayout>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructLayout {
    pub name: Option<String>,
    pub typedef_names: Vec<String>,
    pub fields: Vec<FieldLayout>,
    pub total_size_bytes: usize,
    pub align_bytes: usize,
    pub is_packed: bool,
    pub file_path: PathBuf,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionLayout {
    pub name: Option<String>,
    pub typedef_names: Vec<String>,
    pub variants: Vec<FieldLayout>,
    pub total_size_bytes: usize,
    pub align_bytes: usize,
    pub file_path: PathBuf,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeLayoutGraph {
    pub structs: HashMap<String, StructLayout>,
    pub unions: HashMap<String, UnionLayout>,
    pub typedefs: HashMap<String, TypeKind>,
    pub field_offsets: HashMap<String, HashMap<String, usize>>, // TypeName -> FieldName -> Offset
}

impl TypeLayoutGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_field_offset(&self, type_name: &str, field_name: &str) -> Option<usize> {
        self.field_offsets
            .get(type_name)
            .and_then(|fields| fields.get(field_name).copied())
    }

    pub fn get_struct(&self, name: &str) -> Option<&StructLayout> {
        self.structs.get(name)
    }

    pub fn get_union(&self, name: &str) -> Option<&UnionLayout> {
        self.unions.get(name)
    }

    pub fn get_typedef(&self, name: &str) -> Option<&TypeKind> {
        self.typedefs.get(name)
    }

    pub fn merge(&mut self, other: TypeLayoutGraph) {
        self.structs.extend(other.structs);
        self.unions.extend(other.unions);
        self.typedefs.extend(other.typedefs);
        for (k, v) in other.field_offsets {
            self.field_offsets.entry(k).or_default().extend(v);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousSink {
    pub function_name: String,
    pub sink_type: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub caller: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetAstProfile {
    pub functions: Vec<FunctionSignature>,
    pub structs: Vec<StructInfo>,
    pub dangerous_sinks: Vec<DangerousSink>,
    pub public_headers: Vec<PathBuf>,
    #[serde(default)]
    pub layout_graph: Option<TypeLayoutGraph>,
}
