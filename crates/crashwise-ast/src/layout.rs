use crate::types::*;
use crashwise_core::error::Result;
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

#[derive(Debug)]
enum TypeDeclaration<'a> {
    Struct(Node<'a>, Vec<String>),
    Union(Node<'a>, Vec<String>),
    TypedefAlias {
        name: String,
        target_str: String,
    },
}

pub struct StructLayoutResolver {
    pub known_structs: HashMap<String, StructLayout>,
    pub known_unions: HashMap<String, UnionLayout>,
    pub known_typedefs: HashMap<String, TypeKind>,
}

impl Default for StructLayoutResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl StructLayoutResolver {
    pub fn new() -> Self {
        Self {
            known_structs: HashMap::new(),
            known_unions: HashMap::new(),
            known_typedefs: HashMap::new(),
        }
    }

    /// Primary layout resolver implementing System V AMD64 ABI layout rules.
    pub fn resolve_struct_layouts(
        &mut self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
    ) -> Result<TypeLayoutGraph> {
        let root = tree.root_node();
        let mut graph = TypeLayoutGraph::new();

        let mut declarations = Vec::new();
        self.collect_type_declarations(&root, source, &mut declarations);

        // Multi-pass resolution in source order:
        // Pass 0: Interleaved resolution in source order (unions and structs resolve in declaration order)
        // Pass 1-3: Propagate forward references and transitive typedef aliases
        for _pass in 0..4 {
            for decl in &declarations {
                match decl {
                    TypeDeclaration::TypedefAlias { name, target_str } => {
                        let target_kind = self.classify_type_string(target_str);
                        self.known_typedefs.insert(
                            name.clone(),
                            TypeKind::TypedefRef {
                                name: name.clone(),
                                target: Box::new(target_kind),
                            },
                        );

                        // If target resolves to a known struct, register alias in known_structs & graph
                        let target_clean = target_str.strip_prefix("struct ").unwrap_or(target_str).trim();
                        if let Some(s_layout) = self
                            .known_structs
                            .get(target_clean)
                            .or_else(|| self.known_structs.get(target_str))
                            .cloned()
                        {
                            self.known_structs.insert(name.clone(), s_layout.clone());
                            graph.structs.insert(name.clone(), s_layout.clone());
                            let mut offsets = HashMap::new();
                            for field in &s_layout.fields {
                                offsets.insert(field.name.clone(), field.offset_bytes);
                            }
                            graph.field_offsets.insert(name.clone(), offsets);
                        }

                        // If target resolves to a known union, register alias in known_unions & graph
                        let target_union = target_str.strip_prefix("union ").unwrap_or(target_str).trim();
                        if let Some(u_layout) = self
                            .known_unions
                            .get(target_union)
                            .or_else(|| self.known_unions.get(target_str))
                            .cloned()
                        {
                            self.known_unions.insert(name.clone(), u_layout.clone());
                            graph.unions.insert(name.clone(), u_layout.clone());
                            let mut offsets = HashMap::new();
                            for variant in &u_layout.variants {
                                offsets.insert(variant.name.clone(), 0);
                            }
                            graph.field_offsets.insert(name.clone(), offsets);
                        }
                    }
                    TypeDeclaration::Struct(node, typedef_names) => {
                        if let Some(layout) = self.resolve_struct_node(node, source, file_path, typedef_names) {
                            if let Some(ref name) = layout.name {
                                self.known_structs.insert(name.clone(), layout.clone());
                                self.known_structs.insert(format!("struct {}", name), layout.clone());
                                graph.structs.insert(name.clone(), layout.clone());
                                graph.structs.insert(format!("struct {}", name), layout.clone());

                                let mut offsets = HashMap::new();
                                for field in &layout.fields {
                                    offsets.insert(field.name.clone(), field.offset_bytes);
                                }
                                graph.field_offsets.insert(name.clone(), offsets.clone());
                                graph.field_offsets.insert(format!("struct {}", name), offsets);
                            }

                            for t_name in typedef_names {
                                self.known_structs.insert(t_name.clone(), layout.clone());
                                graph.structs.insert(t_name.clone(), layout.clone());
                                let mut offsets = HashMap::new();
                                for field in &layout.fields {
                                    offsets.insert(field.name.clone(), field.offset_bytes);
                                }
                                graph.field_offsets.insert(t_name.clone(), offsets);

                                self.known_typedefs.insert(
                                    t_name.clone(),
                                    TypeKind::TypedefRef {
                                        name: t_name.clone(),
                                        target: Box::new(TypeKind::StructRef {
                                            name: layout.name.clone().unwrap_or_default(),
                                        }),
                                    },
                                );
                            }
                        }
                    }
                    TypeDeclaration::Union(node, typedef_names) => {
                        if let Some(layout) = self.resolve_union_node(node, source, file_path, typedef_names) {
                            if let Some(ref name) = layout.name {
                                self.known_unions.insert(name.clone(), layout.clone());
                                self.known_unions.insert(format!("union {}", name), layout.clone());
                                graph.unions.insert(name.clone(), layout.clone());
                                graph.unions.insert(format!("union {}", name), layout.clone());

                                let mut offsets = HashMap::new();
                                for variant in &layout.variants {
                                    offsets.insert(variant.name.clone(), 0);
                                }
                                graph.field_offsets.insert(name.clone(), offsets.clone());
                                graph.field_offsets.insert(format!("union {}", name), offsets);
                            }

                            for t_name in typedef_names {
                                self.known_unions.insert(t_name.clone(), layout.clone());
                                graph.unions.insert(t_name.clone(), layout.clone());
                                let mut offsets = HashMap::new();
                                for variant in &layout.variants {
                                    offsets.insert(variant.name.clone(), 0);
                                }
                                graph.field_offsets.insert(t_name.clone(), offsets);

                                self.known_typedefs.insert(
                                    t_name.clone(),
                                    TypeKind::TypedefRef {
                                        name: t_name.clone(),
                                        target: Box::new(TypeKind::UnionRef {
                                            name: layout.name.clone().unwrap_or_default(),
                                        }),
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }

        graph.typedefs = self.known_typedefs.clone();
        Ok(graph)
    }

    fn collect_type_declarations<'a>(
        &mut self,
        node: &Node<'a>,
        source: &'a str,
        declarations: &mut Vec<TypeDeclaration<'a>>,
    ) {
        let kind = node.kind();
        if kind == "type_definition" {
            self.parse_typedef_node(node, source, declarations);
            return;
        }

        if kind == "declaration" {
            // Check if this declaration contains a top-level struct/union definition
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "struct_specifier" && child.child_by_field_name("body").is_some() {
                    declarations.push(TypeDeclaration::Struct(child, Vec::new()));
                } else if child.kind() == "union_specifier" && child.child_by_field_name("body").is_some() {
                    declarations.push(TypeDeclaration::Union(child, Vec::new()));
                }
            }
        } else if kind == "struct_specifier" && node.child_by_field_name("body").is_some() {
            // Only add if parent is not declaration or type_definition (to avoid duplicates)
            let parent_kind = node.parent().map(|p| p.kind());
            if parent_kind != Some("declaration") && parent_kind != Some("type_definition") {
                declarations.push(TypeDeclaration::Struct(*node, Vec::new()));
            }
        } else if kind == "union_specifier" && node.child_by_field_name("body").is_some() {
            let parent_kind = node.parent().map(|p| p.kind());
            if parent_kind != Some("declaration") && parent_kind != Some("type_definition") {
                declarations.push(TypeDeclaration::Union(*node, Vec::new()));
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_type_declarations(&child, source, declarations);
        }
    }

    fn parse_typedef_node<'a>(
        &mut self,
        node: &Node<'a>,
        source: &'a str,
        declarations: &mut Vec<TypeDeclaration<'a>>,
    ) {
        let type_node = node.child_by_field_name("type").or_else(|| {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let k = child.kind();
                if k == "struct_specifier"
                    || k == "union_specifier"
                    || k == "enum_specifier"
                    || k == "primitive_type"
                    || k == "sized_type_specifier"
                    || k == "type_identifier"
                {
                    return Some(child);
                }
            }
            None
        });

        let type_end = type_node.map(|t| t.end_byte()).unwrap_or(0);
        let mut decl_details = Vec::new();

        if let Some(declarator) = node.child_by_field_name("declarator") {
            let details = self.extract_declarator_details(&declarator, source);
            if !details.0.is_empty() {
                decl_details.push(details);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.start_byte() >= type_end && child.kind() != ";" && child.kind() != "," {
                let details = self.extract_declarator_details(&child, source);
                if !details.0.is_empty() && !decl_details.iter().any(|d| d.0 == details.0) {
                    decl_details.push(details);
                }
            }
        }

        if let Some(tnode) = type_node {
            if tnode.kind() == "struct_specifier" && tnode.child_by_field_name("body").is_some() {
                let struct_names = decl_details.iter().map(|d| d.0.clone()).collect();
                declarations.push(TypeDeclaration::Struct(tnode, struct_names));
            } else if tnode.kind() == "union_specifier" && tnode.child_by_field_name("body").is_some() {
                let union_names = decl_details.iter().map(|d| d.0.clone()).collect();
                declarations.push(TypeDeclaration::Union(tnode, union_names));
            } else if let Ok(target_type_str) = tnode.utf8_text(source.as_bytes()) {
                let clean_target = target_type_str.trim().to_string();
                for (name, indirection, _, _, _, _) in &decl_details {
                    let target_with_ptr = if *indirection > 0 {
                        format!("{}{}", clean_target, "*".repeat(*indirection))
                    } else {
                        clean_target.clone()
                    };
                    declarations.push(TypeDeclaration::TypedefAlias {
                        name: name.clone(),
                        target_str: target_with_ptr,
                    });
                }
            }
        }
    }

    fn resolve_struct_node(
        &mut self,
        node: &Node,
        source: &str,
        file_path: &Path,
        typedef_names: &[String],
    ) -> Option<StructLayout> {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string());

        let body = node.child_by_field_name("body")?;
        let is_packed = self.is_node_packed(node, source);

        let mut fields = Vec::new();
        let mut curr_offset: usize = 0;
        let mut max_align: usize = 1;

        let mut active_bitfield_unit: Option<(usize, usize, usize, usize)> = None;
        // (unit_offset, unit_size, unit_align, used_bits)

        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if child.kind() != "field_declaration" {
                continue;
            }

            let field_type_node = child.child_by_field_name("type");
            let is_field_nested_struct = field_type_node
                .as_ref()
                .is_some_and(|t| t.kind() == "struct_specifier" && t.child_by_field_name("body").is_some());
            let is_field_nested_union = field_type_node
                .as_ref()
                .is_some_and(|t| t.kind() == "union_specifier" && t.child_by_field_name("body").is_some());

            let (nested_struct, nested_union) = if is_field_nested_struct {
                let s_node = field_type_node.unwrap();
                let s_layout = self.resolve_struct_node(&s_node, source, file_path, &[]);
                (s_layout.map(Box::new), None)
            } else if is_field_nested_union {
                let u_node = field_type_node.unwrap();
                let u_layout = self.resolve_union_node(&u_node, source, file_path, &[]);
                (None, u_layout.map(Box::new))
            } else {
                (None, None)
            };

            let base_type_str = field_type_node
                .and_then(|t| t.utf8_text(source.as_bytes()).ok())
                .unwrap_or("int");

            // Extract all declarators in this field_declaration (e.g. int a, b, c;)
            let declarators = self.extract_field_declarators(&child, source);

            if declarators.is_empty() {
                // Anonymous struct or union member without declarator name
                if let Some(ref ns) = nested_struct {
                    let align = if is_packed { 1 } else { ns.align_bytes.max(1) };
                    curr_offset = align_up(curr_offset, align);
                    fields.push(FieldLayout {
                        name: format!("__anon_struct_{}", curr_offset),
                        type_kind: TypeKind::StructRef {
                            name: ns.name.clone().unwrap_or_default(),
                        },
                        offset_bytes: curr_offset,
                        size_bytes: ns.total_size_bytes,
                        align_bytes: align,
                        is_bitfield: false,
                        bit_width: None,
                        bit_offset: None,
                        nested_struct: nested_struct.clone(),
                        nested_union: None,
                    });
                    curr_offset += ns.total_size_bytes;
                    max_align = max_align.max(align);
                } else if let Some(ref nu) = nested_union {
                    let align = if is_packed { 1 } else { nu.align_bytes.max(1) };
                    curr_offset = align_up(curr_offset, align);
                    fields.push(FieldLayout {
                        name: format!("__anon_union_{}", curr_offset),
                        type_kind: TypeKind::UnionRef {
                            name: nu.name.clone().unwrap_or_default(),
                        },
                        offset_bytes: curr_offset,
                        size_bytes: nu.total_size_bytes,
                        align_bytes: align,
                        is_bitfield: false,
                        bit_width: None,
                        bit_offset: None,
                        nested_struct: None,
                        nested_union: nested_union.clone(),
                    });
                    curr_offset += nu.total_size_bytes;
                    max_align = max_align.max(align);
                }
                continue;
            }

            for decl_info in declarators {
                let (f_name, indirection, array_len, is_fn_ptr, bitfield_width, fn_params) = decl_info;

                let (mut f_size, f_align, f_type_kind) = if let Some(ref ns) = nested_struct {

                    (
                        ns.total_size_bytes,
                        if is_packed { 1 } else { ns.align_bytes },
                        TypeKind::StructRef {
                            name: ns.name.clone().unwrap_or_default(),
                        },
                    )
                } else if let Some(ref nu) = nested_union {
                    (
                        nu.total_size_bytes,
                        if is_packed { 1 } else { nu.align_bytes },
                        TypeKind::UnionRef {
                            name: nu.name.clone().unwrap_or_default(),
                        },
                    )
                } else if indirection > 0 || is_fn_ptr {
                    // AMD64 pointers are 8 bytes, aligned to 8
                    let pointee_kind = self.classify_type_string(base_type_str);
                    let type_kind = if is_fn_ptr {
                        TypeKind::FunctionPointer {
                            return_type: Box::new(pointee_kind),
                            parameters: fn_params,
                        }
                    } else {
                        TypeKind::Pointer {
                            pointee: Box::new(pointee_kind),
                            indirection,
                            is_const: base_type_str.contains("const"),
                        }
                    };
                    (8, if is_packed { 1 } else { 8 }, type_kind)
                } else {
                    let (s, a) = self.get_type_size_and_align(base_type_str);
                    let base_kind = self.classify_type_string(base_type_str);
                    (s, if is_packed { 1 } else { a }, base_kind)
                };

                // Array modification
                let final_type_kind = if let Some(len) = array_len {
                    f_size *= len;
                    TypeKind::Array {
                        element: Box::new(f_type_kind),
                        len: Some(len),
                    }
                } else {
                    f_type_kind
                };

                // Bitfield handling
                if let Some(width) = bitfield_width {
                    let unit_size = f_size.max(1);
                    let unit_align = if is_packed { 1 } else { f_align.max(1) };
                    max_align = max_align.max(unit_align);

                    if width == 0 {
                        // System V AMD64 ABI & C99/C11 6.7.2.1p11:
                        // Unnamed zero-width bitfield terminates the current unit
                        // and aligns curr_offset to the next unit boundary.
                        let (unit_offset, bit_offset) = if let Some((u_off, u_sz, _u_al, used_bits)) = active_bitfield_unit.take() {
                            curr_offset = u_off + u_sz;
                            curr_offset = align_up(curr_offset, unit_align);
                            (u_off, used_bits as u32)
                        } else {
                            curr_offset = align_up(curr_offset, unit_align);
                            (curr_offset, 0)
                        };

                        fields.push(FieldLayout {
                            name: f_name,
                            type_kind: final_type_kind,
                            offset_bytes: unit_offset,
                            size_bytes: unit_size,
                            align_bytes: unit_align,
                            is_bitfield: true,
                            bit_width: Some(0),
                            bit_offset: Some(bit_offset),
                            nested_struct: nested_struct.clone(),
                            nested_union: nested_union.clone(),
                        });
                        continue;
                    }

                    let (unit_offset, bit_offset) = match active_bitfield_unit {
                        Some((u_off, u_sz, u_al, used_bits))
                            if u_sz == unit_size && (used_bits + width as usize) <= (unit_size * 8) =>
                        {
                            active_bitfield_unit = Some((u_off, u_sz, u_al, used_bits + width as usize));
                            (u_off, used_bits as u32)
                        }
                        _ => {
                            if let Some((u_off, u_sz, _, _)) = active_bitfield_unit {
                                curr_offset = u_off + u_sz;
                            }
                            curr_offset = align_up(curr_offset, unit_align);
                            let u_off = curr_offset;
                            active_bitfield_unit = Some((u_off, unit_size, unit_align, width as usize));
                            (u_off, 0)
                        }
                    };

                    fields.push(FieldLayout {
                        name: f_name,
                        type_kind: final_type_kind,
                        offset_bytes: unit_offset,
                        size_bytes: unit_size,
                        align_bytes: unit_align,
                        is_bitfield: true,
                        bit_width: Some(width),
                        bit_offset: Some(bit_offset),
                        nested_struct: nested_struct.clone(),
                        nested_union: nested_union.clone(),
                    });
                    continue;
                }

                // If prior field was a bitfield and this is not, close the bitfield unit
                if let Some((u_off, u_sz, _, _)) = active_bitfield_unit.take() {
                    curr_offset = u_off + u_sz;
                }

                // Normal field alignment
                curr_offset = align_up(curr_offset, f_align);
                let offset_bytes = curr_offset;
                curr_offset += f_size;
                max_align = max_align.max(f_align);

                fields.push(FieldLayout {
                    name: f_name,
                    type_kind: final_type_kind,
                    offset_bytes,
                    size_bytes: f_size,
                    align_bytes: f_align,
                    is_bitfield: false,
                    bit_width: None,
                    bit_offset: None,
                    nested_struct: nested_struct.clone(),
                    nested_union: nested_union.clone(),
                });
            }
        }

        if let Some((u_off, u_sz, _, _)) = active_bitfield_unit {
            curr_offset = u_off + u_sz;
        }

        // Struct tail padding to multiple of struct alignment
        let struct_align = if is_packed { 1 } else { max_align };
        let total_size_bytes = align_up(curr_offset, struct_align);

        Some(StructLayout {
            name,
            typedef_names: typedef_names.to_vec(),
            fields,
            total_size_bytes,
            align_bytes: struct_align,
            is_packed,
            file_path: file_path.to_path_buf(),
            line_number: node.start_position().row + 1,
        })
    }

    fn resolve_union_node(
        &mut self,
        node: &Node,
        source: &str,
        file_path: &Path,
        typedef_names: &[String],
    ) -> Option<UnionLayout> {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string());

        let body = node.child_by_field_name("body")?;
        let is_packed = self.is_node_packed(node, source);

        let mut variants = Vec::new();
        let mut max_size: usize = 0;
        let mut max_align: usize = 1;

        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if child.kind() != "field_declaration" {
                continue;
            }

            let field_type_node = child.child_by_field_name("type");
            let is_field_nested_struct = field_type_node
                .as_ref()
                .is_some_and(|t| t.kind() == "struct_specifier" && t.child_by_field_name("body").is_some());
            let is_field_nested_union = field_type_node
                .as_ref()
                .is_some_and(|t| t.kind() == "union_specifier" && t.child_by_field_name("body").is_some());

            let (nested_struct, nested_union) = if is_field_nested_struct {
                let s_node = field_type_node.unwrap();
                let s_layout = self.resolve_struct_node(&s_node, source, file_path, &[]);
                (s_layout.map(Box::new), None)
            } else if is_field_nested_union {
                let u_node = field_type_node.unwrap();
                let u_layout = self.resolve_union_node(&u_node, source, file_path, &[]);
                (None, u_layout.map(Box::new))
            } else {
                (None, None)
            };

            let base_type_str = field_type_node
                .and_then(|t| t.utf8_text(source.as_bytes()).ok())
                .unwrap_or("int");

            let declarators = self.extract_field_declarators(&child, source);
            if declarators.is_empty() {
                if let Some(ref ns) = nested_struct {
                    let s_size = ns.total_size_bytes;
                    let s_align = if is_packed { 1 } else { ns.align_bytes.max(1) };
                    max_size = max_size.max(s_size);
                    max_align = max_align.max(s_align);
                    variants.push(FieldLayout {
                        name: format!("__anon_struct_{}", variants.len()),
                        type_kind: TypeKind::StructRef {
                            name: ns.name.clone().unwrap_or_default(),
                        },
                        offset_bytes: 0,
                        size_bytes: s_size,
                        align_bytes: s_align,
                        is_bitfield: false,
                        bit_width: None,
                        bit_offset: None,
                        nested_struct: nested_struct.clone(),
                        nested_union: None,
                    });
                } else if let Some(ref nu) = nested_union {
                    let u_size = nu.total_size_bytes;
                    let u_align = if is_packed { 1 } else { nu.align_bytes.max(1) };
                    max_size = max_size.max(u_size);
                    max_align = max_align.max(u_align);
                    variants.push(FieldLayout {
                        name: format!("__anon_union_{}", variants.len()),
                        type_kind: TypeKind::UnionRef {
                            name: nu.name.clone().unwrap_or_default(),
                        },
                        offset_bytes: 0,
                        size_bytes: u_size,
                        align_bytes: u_align,
                        is_bitfield: false,
                        bit_width: None,
                        bit_offset: None,
                        nested_struct: None,
                        nested_union: nested_union.clone(),
                    });
                }
                continue;
            }

            for decl_info in declarators {
                let (f_name, indirection, array_len, is_fn_ptr, _, fn_params) = decl_info;

                let (mut f_size, f_align, f_type_kind) = if let Some(ref ns) = nested_struct {
                    (
                        ns.total_size_bytes,
                        if is_packed { 1 } else { ns.align_bytes },
                        TypeKind::StructRef {
                            name: ns.name.clone().unwrap_or_default(),
                        },
                    )
                } else if let Some(ref nu) = nested_union {
                    (
                        nu.total_size_bytes,
                        if is_packed { 1 } else { nu.align_bytes },
                        TypeKind::UnionRef {
                            name: nu.name.clone().unwrap_or_default(),
                        },
                    )
                } else if indirection > 0 || is_fn_ptr {
                    let pointee_kind = self.classify_type_string(base_type_str);
                    let type_kind = if is_fn_ptr {
                        TypeKind::FunctionPointer {
                            return_type: Box::new(pointee_kind),
                            parameters: fn_params,
                        }
                    } else {
                        TypeKind::Pointer {
                            pointee: Box::new(pointee_kind),
                            indirection,
                            is_const: base_type_str.contains("const"),
                        }
                    };
                    (8, if is_packed { 1 } else { 8 }, type_kind)
                } else {
                    let (s, a) = self.get_type_size_and_align(base_type_str);
                    let base_kind = self.classify_type_string(base_type_str);
                    (s, if is_packed { 1 } else { a }, base_kind)
                };

                let final_type_kind = if let Some(len) = array_len {
                    f_size *= len;
                    TypeKind::Array {
                        element: Box::new(f_type_kind),
                        len: Some(len),
                    }
                } else {
                    f_type_kind
                };

                max_size = max_size.max(f_size);
                max_align = max_align.max(f_align);

                variants.push(FieldLayout {
                    name: f_name,
                    type_kind: final_type_kind,
                    offset_bytes: 0,
                    size_bytes: f_size,
                    align_bytes: f_align,
                    is_bitfield: false,
                    bit_width: None,
                    bit_offset: None,
                    nested_struct: nested_struct.clone(),
                    nested_union: nested_union.clone(),
                });
            }
        }

        let union_align = if is_packed { 1 } else { max_align };
        let total_size_bytes = align_up(max_size, union_align);

        Some(UnionLayout {
            name,
            typedef_names: typedef_names.to_vec(),
            variants,
            total_size_bytes,
            align_bytes: union_align,
            file_path: file_path.to_path_buf(),
            line_number: node.start_position().row + 1,
        })
    }

    /// Recursively extracts declarator metadata:
    /// (name, indirection, array_len, is_fn_ptr, bitfield_width, fn_params)
    fn extract_declarator_details(
        &self,
        node: &Node,
        source: &str,
    ) -> (String, usize, Option<usize>, bool, Option<u32>, Vec<ParameterInfo>) {
        let mut indirection = 0;
        let mut array_len = None;
        let mut is_fn_ptr = false;
        let bitfield_width = None;
        let mut fn_params = Vec::new();

        let mut curr = *node;

        loop {
            match curr.kind() {
                "field_identifier" | "identifier" | "type_identifier" => {
                    let name = curr.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    return (name, indirection, array_len, is_fn_ptr, bitfield_width, fn_params);
                }
                "pointer_declarator" => {
                    indirection += 1;
                    if let Some(child) = curr.child_by_field_name("declarator") {
                        curr = child;
                    } else {
                        // Pointer to unnamed field
                        return ("".to_string(), indirection, array_len, is_fn_ptr, bitfield_width, fn_params);
                    }
                }
                "array_declarator" => {
                    let mut a_cursor = curr.walk();
                    for child in curr.children(&mut a_cursor) {
                        if child.kind() == "number_literal" {
                            if let Ok(num_str) = child.utf8_text(source.as_bytes()) {
                                if let Ok(num) = num_str.trim().parse::<usize>() {
                                    array_len = Some(array_len.unwrap_or(1) * num);
                                }
                            }
                        }
                    }
                    if let Some(child) = curr.child_by_field_name("declarator") {
                        curr = child;
                    } else {
                        break;
                    }
                }
                "function_declarator" => {
                    is_fn_ptr = true;
                    if let Some(param_list) = curr.child_by_field_name("parameters") {
                        fn_params = self.extract_parameters_from_ast(&param_list, source);
                    }
                    if let Some(child) = curr.child_by_field_name("declarator") {
                        curr = child;
                    } else {
                        break;
                    }
                }
                "parenthesized_declarator" => {
                    let mut cursor = curr.walk();
                    let mut found = false;
                    for child in curr.children(&mut cursor) {
                        if child.kind() != "(" && child.kind() != ")" {
                            curr = child;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        break;
                    }
                }
                _ => {
                    if let Some(child) = curr.child_by_field_name("declarator") {
                        curr = child;
                    } else {
                        let text = curr.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                        return (text, indirection, array_len, is_fn_ptr, bitfield_width, fn_params);
                    }
                }
            }
        }

        ("".to_string(), indirection, array_len, is_fn_ptr, bitfield_width, fn_params)
    }

    #[allow(clippy::type_complexity)]
    fn extract_field_declarators(
        &self,
        field_node: &Node,
        source: &str,
    ) -> Vec<(String, usize, Option<usize>, bool, Option<u32>, Vec<ParameterInfo>)> {
        let mut bitfield_width = None;
        let mut cursor = field_node.walk();
        for child in field_node.children(&mut cursor) {
            if child.kind() == "bitfield_clause" {
                let mut b_cursor = child.walk();
                for b_child in child.children(&mut b_cursor) {
                    if b_child.kind() == "number_literal" {
                        if let Ok(num_str) = b_child.utf8_text(source.as_bytes()) {
                            bitfield_width = num_str.trim().parse::<u32>().ok();
                        }
                    }
                }
            }
        }

        if let Some(width) = bitfield_width {
            let decl = field_node.child_by_field_name("declarator");
            let name = decl
                .map(|d| self.extract_declarator_details(&d, source).0)
                .unwrap_or_default();
            return vec![(name, 0, None, false, Some(width), Vec::new())];
        }


        let mut results = Vec::new();
        let mut cursor = field_node.walk();

        for child in field_node.children(&mut cursor) {
            let k = child.kind();
            if k == "field_identifier"
                || k == "identifier"
                || k == "pointer_declarator"
                || k == "array_declarator"
                || k == "function_declarator"
                || k == "parenthesized_declarator"
            {
                let details = self.extract_declarator_details(&child, source);
                if !details.0.is_empty() {
                    results.push(details);
                }
            }
        }

        // If child_by_field_name is used
        if results.is_empty() {
            if let Some(decl) = field_node.child_by_field_name("declarator") {
                let details = self.extract_declarator_details(&decl, source);
                results.push(details);
            }
        }

        results
    }


    fn extract_parameters_from_ast(&self, param_list: &Node, source: &str) -> Vec<ParameterInfo> {
        let mut params = Vec::new();
        let mut cursor = param_list.walk();

        for child in param_list.children(&mut cursor) {
            if child.kind() == "parameter_declaration" {
                let type_name = child
                    .child_by_field_name("type")
                    .and_then(|t| t.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("void")
                    .to_string();

                let mut is_pointer = false;
                let mut is_const = false;
                let mut param_name = String::new();

                // Inspect AST nodes for qualifier and pointer declarator
                let mut p_cursor = child.walk();
                for p_child in child.children(&mut p_cursor) {
                    if p_child.kind() == "type_qualifier" {
                        if let Ok(t) = p_child.utf8_text(source.as_bytes()) {
                            if t.trim() == "const" {
                                is_const = true;
                            }
                        }
                    } else if p_child.kind() == "pointer_declarator" {
                        is_pointer = true;
                        if let Some(inner) = p_child.child_by_field_name("declarator") {
                            param_name = inner.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                        }
                    } else if p_child.kind() == "identifier" {
                        param_name = p_child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    }
                }

                if let Some(decl) = child.child_by_field_name("declarator") {
                    if decl.kind() == "pointer_declarator" {
                        is_pointer = true;
                    }
                    if param_name.is_empty() {
                        param_name = decl.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    }
                }

                params.push(ParameterInfo {
                    name: param_name,
                    type_name,
                    is_pointer,
                    is_const,
                });
            }
        }

        params
    }

    fn is_node_packed(&self, node: &Node, source: &str) -> bool {
        // 1. Direct attribute on struct/union specifier
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "attribute_specifier" || child.kind() == "ms_declspec_modifier" {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    if text.contains("packed") {
                        return true;
                    }
                }
            }
        }

        // 2. Attribute on parent declaration or type_definition
        if let Some(parent) = node.parent() {
            if parent.kind() == "declaration" || parent.kind() == "type_definition" {
                let mut p_cursor = parent.walk();
                for child in parent.children(&mut p_cursor) {
                    if child.kind() == "attribute_specifier" || child.kind() == "ms_declspec_modifier" {
                        if let Ok(text) = child.utf8_text(source.as_bytes()) {
                            if text.contains("packed") {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // 3. Scan backwards for active #pragma pack(1) preceding this node
        if node.start_byte() <= source.len() {
            let prefix = &source[..node.start_byte()];
            for line in prefix.lines().rev() {
                let trimmed = line.trim();
                if trimmed.starts_with("#pragma") && trimmed.contains("pack") {
                    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
                    if compact.contains("pack(1)") || compact.contains("pack(push,1)") {
                        return true;
                    }
                    if compact.contains("pack()")
                        || compact.contains("pack(pop)")
                        || compact.contains("pack(2)")
                        || compact.contains("pack(4)")
                        || compact.contains("pack(8)")
                    {
                        return false;
                    }
                }
            }
        }

        false
    }

    /// Returns (size_bytes, align_bytes) according to AMD64 System V ABI.
    pub fn get_type_size_and_align(&self, type_str: &str) -> (usize, usize) {
        let mut clean = type_str
            .replace("const", "")
            .replace("volatile", "")
            .replace("restrict", "")
            .trim()
            .to_string();

        for _ in 0..32 {
            if clean.ends_with('*') {
                return (8, 8);
            }

            if let Some(layout) = primitive_layout(&clean) {
                return layout;
            }

            // Check known structs
            if let Some(s) = self.known_structs.get(&clean) {
                return (s.total_size_bytes, s.align_bytes);
            }
            if let Some(stripped) = clean.strip_prefix("struct ") {
                if let Some(s) = self.known_structs.get(stripped.trim()) {
                    return (s.total_size_bytes, s.align_bytes);
                }
            }

            // Check known unions
            if let Some(u) = self.known_unions.get(&clean) {
                return (u.total_size_bytes, u.align_bytes);
            }
            if let Some(stripped) = clean.strip_prefix("union ") {
                if let Some(u) = self.known_unions.get(stripped.trim()) {
                    return (u.total_size_bytes, u.align_bytes);
                }
            }

            // Check known typedefs
            if let Some(t) = self.known_typedefs.get(&clean) {
                match t {
                    TypeKind::Primitive { size_bytes, align_bytes, .. } => return (*size_bytes, *align_bytes),
                    TypeKind::Pointer { .. } | TypeKind::FunctionPointer { .. } => return (8, 8),
                    TypeKind::StructRef { name } => {
                        clean = name.clone();
                        continue;
                    }
                    TypeKind::UnionRef { name } => {
                        clean = name.clone();
                        continue;
                    }
                    TypeKind::TypedefRef { target, name } => {
                        match target.as_ref() {
                            TypeKind::Primitive { size_bytes, align_bytes, .. } => return (*size_bytes, *align_bytes),
                            TypeKind::Pointer { .. } | TypeKind::FunctionPointer { .. } => return (8, 8),
                            TypeKind::StructRef { name: s_name } => {
                                clean = s_name.clone();
                                continue;
                            }
                            TypeKind::UnionRef { name: u_name } => {
                                clean = u_name.clone();
                                continue;
                            }
                            TypeKind::TypedefRef { name: next_name, .. } => {
                                clean = next_name.clone();
                                continue;
                            }
                            _ => {
                                clean = name.clone();
                                continue;
                            }
                        }
                    }
                    _ => {}
                }
            }

            break;
        }

        // Default to word size for unknown struct/types
        (8, 8)
    }

    fn classify_type_string(&self, type_str: &str) -> TypeKind {
        let clean = type_str
            .replace("const", "")
            .replace("volatile", "")
            .replace("restrict", "")
            .trim()
            .to_string();

        if clean.ends_with('*') {
            let pointee_str = clean.trim_end_matches('*').trim();
            return TypeKind::Pointer {
                pointee: Box::new(self.classify_type_string(pointee_str)),
                indirection: clean.chars().filter(|&c| c == '*').count(),
                is_const: type_str.contains("const"),
            };
        }

        if let Some((size_bytes, align_bytes)) = primitive_layout(&clean) {
            return TypeKind::Primitive {
                name: clean,
                size_bytes,
                align_bytes,
            };
        }

        if let Some(stripped) = clean.strip_prefix("struct ") {
            return TypeKind::StructRef {
                name: stripped.trim().to_string(),
            };
        }

        if let Some(stripped) = clean.strip_prefix("union ") {
            return TypeKind::UnionRef {
                name: stripped.trim().to_string(),
            };
        }

        if let Some(stripped) = clean.strip_prefix("enum ") {
            return TypeKind::EnumRef {
                name: stripped.trim().to_string(),
                variants: Vec::new(),
            };
        }

        // Check known structs
        if let Some(s) = self.known_structs.get(&clean) {
            return TypeKind::StructRef {
                name: s.name.clone().unwrap_or_else(|| clean.clone()),
            };
        }

        // Check known unions
        if let Some(u) = self.known_unions.get(&clean) {
            return TypeKind::UnionRef {
                name: u.name.clone().unwrap_or_else(|| clean.clone()),
            };
        }

        // Check known typedefs
        if let Some(t) = self.known_typedefs.get(&clean) {
            return t.clone();
        }

        TypeKind::Primitive {
            name: clean,
            size_bytes: 8,
            align_bytes: 8,
        }
    }
}

fn align_up(offset: usize, align: usize) -> usize {
    if align == 0 {
        return offset;
    }
    (offset + align - 1) & !(align - 1)
}

pub fn primitive_layout(name: &str) -> Option<(usize, usize)> {
    let normalized = name.trim();
    match normalized {
        "void" => Some((0, 1)),
        "bool" | "_Bool" => Some((1, 1)),
        "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t" | "int_least8_t" | "uint_least8_t"
        | "int_fast8_t" | "uint_fast8_t" => Some((1, 1)),
        "short" | "signed short" | "unsigned short" | "short int" | "signed short int"
        | "unsigned short int" | "int16_t" | "uint16_t" | "int_least16_t" | "uint_least16_t" => {
            Some((2, 2))
        }
        "int" | "signed int" | "unsigned int" | "signed" | "unsigned" | "int32_t" | "uint32_t"
        | "int_least32_t" | "uint_least32_t" | "int_fast16_t" | "uint_fast16_t" | "int_fast32_t"
        | "uint_fast32_t" | "wchar_t" | "char32_t" => Some((4, 4)),
        "long" | "signed long" | "unsigned long" | "long int" | "signed long int" | "unsigned long int"
        | "long long" | "signed long long" | "unsigned long long" | "long long int"
        | "signed long long int" | "unsigned long long int" | "int64_t" | "uint64_t" | "int_least64_t"
        | "uint_least64_t" | "int_fast64_t" | "uint_fast64_t" | "intmax_t" | "uintmax_t" | "size_t"
        | "ssize_t" | "intptr_t" | "uintptr_t" | "ptrdiff_t" | "time_t" | "off_t" => Some((8, 8)),
        "float" => Some((4, 4)),
        "double" => Some((8, 8)),
        "long double" => Some((16, 16)),
        "__int128" | "unsigned __int128" => Some((16, 16)),
        _ => None,
    }
}
