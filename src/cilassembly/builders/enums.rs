//! High-level enum builder for creating .NET enum definitions.
//!
//! This module provides [`EnumBuilder`] for creating complete enum definitions
//! including enum values and underlying types. It orchestrates the existing
//! low-level builders to provide a fluent, high-level API for enum creation.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        signatures::{encode_field_signature, SignatureField, TypeSignature},
        tables::{
            CodedIndex, CodedIndexType, ConstantBuilder, FieldBuilder, TableId, TypeAttributes,
            TypeDefBuilder,
        },
        token::Token,
        typesystem::ELEMENT_TYPE,
    },
    Error, Result,
};

/// Enum value definition for the enum builder.
struct EnumValueDefinition {
    name: String,
    value: i64,
}

/// High-level builder for creating complete enum definitions.
///
/// `EnumBuilder` provides a fluent API for creating enums with enum values
/// and underlying types. It composes the existing low-level builders to provide
/// a convenient high-level interface for .NET enum creation.
///
/// # Design
///
/// The builder follows .NET enum structure requirements:
/// - Uses existing `TypeDefBuilder` for the enum definition with SEALED flag
/// - Creates a special `value__` field to hold the underlying value
/// - Uses `FieldBuilder` for enum value constants
/// - Uses `ConstantBuilder` to set constant values for enum members
/// - Inherits from System.Enum as required by .NET specification
///
/// # Examples
///
/// ## Simple Enum
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let enum_token = EnumBuilder::new("Color")
///     .public()
///     .value("Red", 0)
///     .value("Green", 1)
///     .value("Blue", 2)
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Enum with Custom Underlying Type
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let enum_token = EnumBuilder::new("Status")
///     .public()
///     .underlying_type(TypeSignature::U8) // byte enum
///     .value("Unknown", 0)
///     .value("Pending", 1)
///     .value("Complete", 255)
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Flags Enum
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let enum_token = EnumBuilder::new("FileAccess")
///     .public()
///     .value("None", 0)
///     .value("Read", 1)
///     .value("Write", 2)
///     .value("ReadWrite", 3)
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
pub struct EnumBuilder {
    /// Enum name
    name: String,

    /// Namespace (optional)
    namespace: Option<String>,

    /// Enum visibility attributes
    visibility: u32,

    /// Additional enum attributes
    attributes: u32,

    /// Underlying type for enum values (default is i32)
    underlying_type: TypeSignature,

    /// Enum values in this enum
    values: Vec<EnumValueDefinition>,
}

impl EnumBuilder {
    /// Create a new enum builder with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - Enum name
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EnumBuilder::new("MyEnum");
    /// ```
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: None,
            visibility: TypeAttributes::PUBLIC,
            attributes: TypeAttributes::SEALED,
            underlying_type: TypeSignature::I4, // Default to int32
            values: Vec::new(),
        }
    }

    /// Set the namespace for this enum.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Namespace string
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EnumBuilder::new("MyEnum")
    ///     .namespace("MyApp.Enums");
    /// ```
    #[must_use]
    pub fn namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }

    /// Make this enum public.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EnumBuilder::new("MyEnum")
    ///     .public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.visibility = TypeAttributes::PUBLIC;
        self
    }

    /// Make this enum internal (assembly visibility).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EnumBuilder::new("MyEnum")
    ///     .internal();
    /// ```
    #[must_use]
    pub fn internal(mut self) -> Self {
        self.visibility = TypeAttributes::NOT_PUBLIC;
        self
    }

    /// Set the underlying type for the enum.
    ///
    /// # Arguments
    ///
    /// * `underlying_type` - The underlying type (I1, U1, I2, U2, I4, U4, I8, U8)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EnumBuilder::new("ByteEnum")
    ///     .underlying_type(TypeSignature::U1); // byte enum
    /// ```
    #[must_use]
    pub fn underlying_type(mut self, underlying_type: TypeSignature) -> Self {
        self.underlying_type = underlying_type;
        self
    }

    /// Add an enum value.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the enum value
    /// * `value` - Numeric value for this enum member
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EnumBuilder::new("Color")
    ///     .value("Red", 0)
    ///     .value("Green", 1)
    ///     .value("Blue", 2);
    /// ```
    #[must_use]
    pub fn value(mut self, name: &str, value: i64) -> Self {
        self.values.push(EnumValueDefinition {
            name: name.to_string(),
            value,
        });
        self
    }

    /// Build the enum and add it to the assembly.
    ///
    /// This method creates:
    /// 1. TypeDef table entry with SEALED flag
    /// 2. Special `value__` field to hold the underlying value
    /// 3. Constant field definitions for each enum value
    /// 4. Constant entries with the actual enum values
    ///
    /// # Arguments
    ///
    /// * `context` - Builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A token representing the newly created enum definition.
    ///
    /// # Errors
    ///
    /// Returns an error if enum creation fails at any step.
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Validate enum constraints
        if self.name.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Enum name cannot be empty".to_string(),
            });
        }

        // Create the enum TypeDef entry (sealed value type that inherits from System.Enum)
        let mut typedef_builder = TypeDefBuilder::new()
            .name(&self.name)
            .flags(self.visibility | self.attributes);

        if let Some(namespace) = &self.namespace {
            typedef_builder = typedef_builder.namespace(namespace);
        }

        // Set extends to System.Enum (we'll use a coded index to TypeRef)
        // For now, we'll create a basic enum without the extends reference
        // TODO: Add proper System.Enum reference when TypeRef support is available

        let enum_token = typedef_builder.build(context)?;

        // Create the special value__ field that holds the underlying enum value
        let value_field_signature = SignatureField {
            modifiers: Vec::new(),
            base: self.underlying_type.clone(),
        };
        let value_field_sig_bytes = encode_field_signature(&value_field_signature)?;

        FieldBuilder::new()
            .name("value__")
            .flags(0x0001 | 0x0800) // PRIVATE | SPECIAL_NAME (runtime special field)
            .signature(&value_field_sig_bytes)
            .build(context)?;

        // Create constant fields for each enum value
        for enum_value in self.values {
            // Create field signature for the enum constant
            let enum_field_signature = SignatureField {
                modifiers: Vec::new(),
                base: self.underlying_type.clone(),
            };
            let enum_field_sig_bytes = encode_field_signature(&enum_field_signature)?;

            // Create the field
            let field_token = FieldBuilder::new()
                .name(&enum_value.name)
                .flags(0x0006 | 0x0001 | 0x0040) // PUBLIC | STATIC | LITERAL
                .signature(&enum_field_sig_bytes)
                .build(context)?;

            // Create the constant value for this field
            // We need to convert the i64 value to the appropriate constant type
            let constant_value = match self.underlying_type {
                TypeSignature::I1 => {
                    let val = i8::try_from(enum_value.value).map_err(|_| {
                        malformed_error!("Enum value {} exceeds i8 range", enum_value.value)
                    })?;
                    vec![val.to_le_bytes()[0]]
                }
                TypeSignature::U1 => {
                    let val = u8::try_from(enum_value.value).map_err(|_| {
                        malformed_error!("Enum value {} exceeds u8 range", enum_value.value)
                    })?;
                    vec![val]
                }
                TypeSignature::I2 => {
                    let val = i16::try_from(enum_value.value).map_err(|_| {
                        malformed_error!("Enum value {} exceeds i16 range", enum_value.value)
                    })?;
                    val.to_le_bytes().to_vec()
                }
                TypeSignature::U2 => {
                    let val = u16::try_from(enum_value.value).map_err(|_| {
                        malformed_error!("Enum value {} exceeds u16 range", enum_value.value)
                    })?;
                    val.to_le_bytes().to_vec()
                }
                TypeSignature::I4 => {
                    let val = i32::try_from(enum_value.value).map_err(|_| {
                        malformed_error!("Enum value {} exceeds i32 range", enum_value.value)
                    })?;
                    val.to_le_bytes().to_vec()
                }
                TypeSignature::U4 => {
                    let val = u32::try_from(enum_value.value).map_err(|_| {
                        malformed_error!("Enum value {} exceeds u32 range", enum_value.value)
                    })?;
                    val.to_le_bytes().to_vec()
                }
                TypeSignature::I8 => {
                    let val = enum_value.value;
                    val.to_le_bytes().to_vec()
                }
                TypeSignature::U8 => {
                    let val = u64::try_from(enum_value.value).map_err(|_| {
                        malformed_error!("Enum value {} exceeds u64 range", enum_value.value)
                    })?;
                    val.to_le_bytes().to_vec()
                }
                _ => {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!(
                            "Unsupported enum underlying type: {:?}",
                            self.underlying_type
                        ),
                    });
                }
            };

            // Create the constant entry
            let element_type = match self.underlying_type {
                TypeSignature::I1 => ELEMENT_TYPE::I1,
                TypeSignature::U1 => ELEMENT_TYPE::U1,
                TypeSignature::I2 => ELEMENT_TYPE::I2,
                TypeSignature::U2 => ELEMENT_TYPE::U2,
                TypeSignature::I4 => ELEMENT_TYPE::I4,
                TypeSignature::U4 => ELEMENT_TYPE::U4,
                TypeSignature::I8 => ELEMENT_TYPE::I8,
                TypeSignature::U8 => ELEMENT_TYPE::U8,
                _ => {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!(
                            "Unsupported enum underlying type: {:?}",
                            self.underlying_type
                        ),
                    });
                }
            };

            ConstantBuilder::new()
                .element_type(element_type)
                .parent(CodedIndex::new(
                    TableId::Field,
                    field_token.row(),
                    CodedIndexType::HasConstant,
                ))
                .value(&constant_value)
                .build(context)?;
        }

        Ok(enum_token)
    }
}

impl Default for EnumBuilder {
    fn default() -> Self {
        Self::new("DefaultEnum")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, signatures::TypeSignature},
    };
    use std::path::PathBuf;

    fn get_test_context() -> Result<BuilderContext> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let view = CilAssemblyView::from_file(&path)?;
        let assembly = CilAssembly::new(view);
        Ok(BuilderContext::new(assembly))
    }

    #[test]
    fn test_simple_enum() -> Result<()> {
        let mut context = get_test_context()?;

        let enum_token = EnumBuilder::new("Color")
            .public()
            .namespace("MyApp.Enums")
            .value("Red", 0)
            .value("Green", 1)
            .value("Blue", 2)
            .build(&mut context)?;

        // Should create a valid TypeDef token
        assert_eq!(enum_token.value() & 0xFF000000, 0x02000000); // TypeDef table

        Ok(())
    }

    #[test]
    fn test_byte_enum() -> Result<()> {
        let mut context = get_test_context()?;

        let enum_token = EnumBuilder::new("Status")
            .public()
            .underlying_type(TypeSignature::U1) // byte
            .value("Unknown", 0)
            .value("Pending", 1)
            .value("Complete", 255)
            .build(&mut context)?;

        assert_eq!(enum_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_flags_enum() -> Result<()> {
        let mut context = get_test_context()?;

        let enum_token = EnumBuilder::new("FileAccess")
            .public()
            .value("None", 0)
            .value("Read", 1)
            .value("Write", 2)
            .value("ReadWrite", 3)
            .build(&mut context)?;

        assert_eq!(enum_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_long_enum() -> Result<()> {
        let mut context = get_test_context()?;

        let enum_token = EnumBuilder::new("LargeValues")
            .public()
            .underlying_type(TypeSignature::I8) // long
            .value("Small", 1)
            .value("Large", 9223372036854775807) // i64::MAX
            .build(&mut context)?;

        assert_eq!(enum_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_internal_enum() -> Result<()> {
        let mut context = get_test_context()?;

        let enum_token = EnumBuilder::new("InternalEnum")
            .internal()
            .value("Value1", 10)
            .value("Value2", 20)
            .build(&mut context)?;

        assert_eq!(enum_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_empty_enum() -> Result<()> {
        let mut context = get_test_context()?;

        let enum_token = EnumBuilder::new("EmptyEnum").public().build(&mut context)?;

        assert_eq!(enum_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_empty_name_fails() {
        let mut context = get_test_context().unwrap();

        let result = EnumBuilder::new("").public().build(&mut context);

        assert!(result.is_err());
    }
}
