//! Field builders for creating mock field instances with various configurations
//!
//! This module provides builders for creating Field instances with access modifiers,
//! layouts, marshalling descriptors, constants, and other field-related metadata.

use std::sync::{Arc, OnceLock};

use crate::metadata::{
    marshalling::{MarshallingInfo, NativeType},
    signatures::{SignatureField, TypeSignature},
    tables::{Field, FieldAttributes, FieldRc},
    token::Token,
    typesystem::{CilFlavor, CilPrimitive, CilTypeRc},
};

/// Field layout types for explicit field positioning
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldLayout {
    /// Automatic layout determined by runtime
    Auto,
    /// Sequential layout in declaration order
    Sequential,
    /// Explicit layout with specific offset
    Explicit(u32),
}

/// Field marshalling configurations for P/Invoke scenarios
#[derive(Debug, Clone)]
pub enum FieldMarshalling {
    /// No marshalling (managed field)
    None,
    /// ANSI string marshalling
    LPStr,
    /// Unicode string marshalling  
    LPWStr,
    /// COM BSTR marshalling
    BStr,
    /// Fixed-size array marshalling
    FixedArray(u32),
    /// Custom marshalling info
    Custom(MarshallingInfo),
}

/// Constant value types for field default values
#[derive(Debug, Clone)]
pub enum FieldConstant {
    /// Boolean constant
    Bool(bool),
    /// 8-bit signed integer
    I1(i8),
    /// 8-bit unsigned integer
    U1(u8),
    /// 16-bit signed integer
    I2(i16),
    /// 16-bit unsigned integer
    U2(u16),
    /// 32-bit signed integer
    I4(i32),
    /// 32-bit unsigned integer
    U4(u32),
    /// 64-bit signed integer
    I8(i64),
    /// 64-bit unsigned integer
    U8(u64),
    /// 32-bit floating point
    R4(f32),
    /// 64-bit floating point
    R8(f64),
    /// String constant
    String(String),
    /// Null reference
    Null,
}

/// Builder for creating mock Field instances with various configurations
pub struct FieldBuilder {
    rid: u32,
    name: String,
    field_type: Option<CilTypeRc>,
    flags: u32,
    layout: FieldLayout,
    marshalling: FieldMarshalling,
    constant: Option<FieldConstant>,
    rva: Option<u32>, // For fields with RVA (static data)
}

impl FieldBuilder {
    pub fn new(name: &str, field_type: CilTypeRc) -> Self {
        Self {
            rid: 1,
            name: name.to_string(),
            field_type: Some(field_type),
            flags: FieldAttributes::PUBLIC,
            layout: FieldLayout::Auto,
            marshalling: FieldMarshalling::None,
            constant: None,
            rva: None,
        }
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_access_private(mut self) -> Self {
        self.flags = (self.flags & !FieldAttributes::FIELD_ACCESS_MASK) | FieldAttributes::PRIVATE;
        self
    }

    pub fn with_access_public(mut self) -> Self {
        self.flags = (self.flags & !FieldAttributes::FIELD_ACCESS_MASK) | FieldAttributes::PUBLIC;
        self
    }

    pub fn with_access_family(mut self) -> Self {
        self.flags = (self.flags & !FieldAttributes::FIELD_ACCESS_MASK) | FieldAttributes::FAMILY;
        self
    }

    pub fn with_access_assembly(mut self) -> Self {
        self.flags = (self.flags & !FieldAttributes::FIELD_ACCESS_MASK) | FieldAttributes::ASSEMBLY;
        self
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_static(mut self) -> Self {
        self.flags |= FieldAttributes::STATIC;
        self
    }

    pub fn with_initonly(mut self) -> Self {
        self.flags |= FieldAttributes::INIT_ONLY;
        self
    }

    pub fn with_literal(mut self) -> Self {
        self.flags |= FieldAttributes::LITERAL;
        self
    }

    pub fn with_layout(mut self, layout: FieldLayout) -> Self {
        self.layout = layout;
        self
    }

    pub fn with_marshalling(mut self, marshalling: FieldMarshalling) -> Self {
        self.marshalling = marshalling;
        self
    }

    pub fn with_constant(mut self, constant: FieldConstant) -> Self {
        self.constant = Some(constant);
        self.flags |= FieldAttributes::HAS_DEFAULT | FieldAttributes::LITERAL;
        self
    }

    pub fn with_rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self.flags |= FieldAttributes::HAS_FIELD_RVA;
        self
    }

    /// Create a private field
    pub fn private_field(name: &str, field_type: CilTypeRc) -> Self {
        Self::new(name, field_type).with_access_private()
    }

    /// Create a public static field
    pub fn public_static_field(name: &str, field_type: CilTypeRc) -> Self {
        Self::new(name, field_type)
            .with_access_public()
            .with_static()
    }

    /// Create a readonly field
    pub fn readonly_field(name: &str, field_type: CilTypeRc) -> Self {
        Self::new(name, field_type).with_initonly()
    }

    /// Create a const field with a value
    pub fn const_field(name: &str, field_type: CilTypeRc, value: FieldConstant) -> Self {
        Self::new(name, field_type)
            .with_access_public()
            .with_static()
            .with_constant(value)
    }

    /// Create a field with explicit layout offset
    pub fn explicit_layout_field(name: &str, field_type: CilTypeRc, offset: u32) -> Self {
        Self::new(name, field_type).with_layout(FieldLayout::Explicit(offset))
    }

    /// Create a marshalled P/Invoke field
    pub fn pinvoke_field(name: &str, field_type: CilTypeRc, marshalling: FieldMarshalling) -> Self {
        Self::new(name, field_type).with_marshalling(marshalling)
    }

    /// Create a backing field for an auto-property
    pub fn backing_field(property_name: &str, field_type: CilTypeRc) -> Self {
        Self::private_field(&format!("<{property_name}>k__BackingField"), field_type)
            .with_flags(FieldAttributes::COMPILER_CONTROLLED)
    }

    /// Create a simple int32 field
    pub fn simple_i4_field(name: &str) -> Self {
        let i4_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000001),
            "System".to_string(),
            "Int32".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(CilFlavor::I4),
        ));
        Self::new(name, i4_type)
    }

    /// Create a simple string field
    pub fn simple_string_field(name: &str) -> Self {
        let string_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000002),
            "System".to_string(),
            "String".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(CilFlavor::String),
        ));
        Self::new(name, string_type)
    }

    /// Create a simple boolean field
    pub fn simple_boolean_field(name: &str) -> Self {
        let bool_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000003),
            "System".to_string(),
            "Boolean".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(CilFlavor::Boolean),
        ));
        Self::new(name, bool_type)
    }

    /// Create a simple float32 field  
    pub fn simple_r4_field(name: &str) -> Self {
        let r4_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000004),
            "System".to_string(),
            "Single".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(CilFlavor::R4),
        ));
        Self::new(name, r4_type)
    }

    /// Create a simple object field
    pub fn simple_object_field(name: &str) -> Self {
        let object_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000005),
            "System".to_string(),
            "Object".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(CilFlavor::Object),
        ));
        Self::new(name, object_type)
    }

    pub fn build(self) -> FieldRc {
        // Compute optional values before moving self
        let offset = self.compute_offset();
        let marshal_info = self.create_marshalling_info();

        // Create field signature based on the field type
        let signature = if let Some(ref field_type) = self.field_type {
            match field_type.flavor() {
                CilFlavor::I4 => SignatureField {
                    modifiers: Vec::new(),
                    base: TypeSignature::I4,
                },
                CilFlavor::String => SignatureField {
                    modifiers: Vec::new(),
                    base: TypeSignature::String,
                },
                CilFlavor::Boolean => SignatureField {
                    modifiers: Vec::new(),
                    base: TypeSignature::Boolean,
                },
                CilFlavor::R4 => SignatureField {
                    modifiers: Vec::new(),
                    base: TypeSignature::R4,
                },
                CilFlavor::Object => SignatureField {
                    modifiers: Vec::new(),
                    base: TypeSignature::Object,
                },
                _ => SignatureField {
                    modifiers: Vec::new(),
                    base: TypeSignature::I4, // Default fallback
                },
            }
        } else {
            SignatureField {
                modifiers: Vec::new(),
                base: TypeSignature::I4, // Default fallback
            }
        };

        // Create field with OnceLock fields
        let field = Field {
            rid: self.rid,
            token: Token::new(0x04000000 + self.rid),
            offset: self.rid as usize,
            flags: self.flags,
            name: self.name,
            signature,
            default: OnceLock::new(),
            rva: OnceLock::new(),
            layout: OnceLock::new(),
            marshal: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        };

        let field_rc = Arc::new(field);

        // Set optional values if they exist (simplified)
        if self.constant.is_some() {
            // For mock purposes, just create a simple primitive
            let primitive = CilPrimitive {
                kind: crate::metadata::typesystem::CilPrimitiveKind::I4,
                data: crate::metadata::typesystem::CilPrimitiveData::I4(42),
            };
            let _ = field_rc.default.set(primitive);
        }

        if let Some(rva_val) = self.rva {
            let _ = field_rc.rva.set(rva_val);
        }

        if let Some(offset_val) = offset {
            let _ = field_rc.layout.set(offset_val);
        }

        if let Some(marshal) = marshal_info {
            let _ = field_rc.marshal.set(marshal);
        }

        field_rc
    }

    /// Compute field offset for explicit layout
    fn compute_offset(&self) -> Option<u32> {
        match self.layout {
            FieldLayout::Explicit(offset) => Some(offset),
            _ => None,
        }
    }

    /// Create marshalling info if specified (simplified)
    fn create_marshalling_info(&self) -> Option<MarshallingInfo> {
        match &self.marshalling {
            FieldMarshalling::None => None,
            FieldMarshalling::LPStr => Some(MarshallingInfo {
                primary_type: NativeType::LPStr {
                    size_param_index: None,
                },
                additional_types: Vec::new(),
            }),
            FieldMarshalling::LPWStr => Some(MarshallingInfo {
                primary_type: NativeType::LPWStr {
                    size_param_index: None,
                },
                additional_types: Vec::new(),
            }),
            FieldMarshalling::BStr => Some(MarshallingInfo {
                primary_type: NativeType::BStr,
                additional_types: Vec::new(),
            }),
            FieldMarshalling::FixedArray(size) => Some(MarshallingInfo {
                primary_type: NativeType::FixedArray {
                    size: *size,
                    element_type: None,
                },
                additional_types: Vec::new(),
            }),
            FieldMarshalling::Custom(info) => Some(info.clone()),
        }
    }
}

impl Default for FieldBuilder {
    fn default() -> Self {
        // We need a default type, let's create a simple one
        let default_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000001),
            "System".to_string(),
            "Int32".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(CilFlavor::I4),
        ));

        Self::new("DefaultField", default_type)
    }
}

/// Builder for creating field layout scenarios
pub struct FieldLayoutBuilder {
    fields: Vec<FieldBuilder>,
    layout_kind: u32, // 0=Auto, 1=Sequential, 2=Explicit
    packing_size: Option<u16>,
    class_size: Option<u32>,
}

impl FieldLayoutBuilder {
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
            layout_kind: 0, // Auto layout
            packing_size: None,
            class_size: None,
        }
    }

    pub fn with_auto_layout(mut self) -> Self {
        self.layout_kind = 0;
        self
    }

    pub fn with_sequential_layout(mut self) -> Self {
        self.layout_kind = 1;
        self
    }

    pub fn with_explicit_layout(mut self) -> Self {
        self.layout_kind = 2;
        self
    }

    pub fn with_packing_size(mut self, size: u16) -> Self {
        self.packing_size = Some(size);
        self
    }

    pub fn with_class_size(mut self, size: u32) -> Self {
        self.class_size = Some(size);
        self
    }

    pub fn add_field(mut self, field: FieldBuilder) -> Self {
        self.fields.push(field);
        self
    }

    pub fn build(self) -> Vec<FieldRc> {
        self.fields.into_iter().map(|f| f.build()).collect()
    }
}

impl Default for FieldLayoutBuilder {
    fn default() -> Self {
        Self::new()
    }
}
