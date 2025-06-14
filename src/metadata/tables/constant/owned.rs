use std::sync::Arc;

use crate::{
    metadata::{
        token::Token,
        typesystem::{CilPrimitive, CilTypeReference},
    },
    Result,
};

/// The Constant table stores constant values for fields, parameters, and properties. Similar to `ConstantRaw` but
/// with resolved indexes and owned data
pub struct Constant {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 1-byte constant, followed by a 1-byte padding zero); see §II.23.1.16. The encoding of Type for the
    /// nullref value for `FieldInit` in ilasm (§II.16.2) is `ELEMENT_TYPE_CLASS` with a Value of a 4-byte zero.
    /// Unlike uses of `ELEMENT_TYPE_CLASS` in signatures, this one is not followed by a type toke
    pub c_type: u8,
    /// an index into the `Param`, `Field`, or `Property` table; more precisely, a `HasConstant` (§II.24.2.6) coded index
    pub parent: CilTypeReference,
    /// The const value
    pub value: Arc<CilPrimitive>,
}

impl Constant {
    /// Apply a `Constant` to set the default value on the parent entity (field, parameter, or property)
    ///
    /// # Errors
    /// Returns an error if the default value is already set for the parent entity,
    /// or if the constant value is not compatible with the target type
    pub fn apply(&self) -> Result<()> {
        match &self.parent {
            CilTypeReference::Field(field) => {
                if !field.signature.base.accepts_constant(&self.value) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with field type: {:?} (token: {})",
                        self.value.kind,
                        field.signature.base,
                        self.token.value()
                    ));
                }

                field
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for field"))
            }
            CilTypeReference::Param(param) => {
                if let Some(param_type) = param.base.get() {
                    if let Some(param_type_strong) = param_type.upgrade() {
                        if !param_type_strong.accepts_constant(&self.value) {
                            return Err(malformed_error!(
                                "Constant type {:?} is not compatible with parameter type {} (token: {})",
                                self.value.kind,
                                param_type_strong.fullname(),
                                self.token.value()
                            ));
                        }
                    }
                }

                param
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for param"))
            }
            CilTypeReference::Property(property) => {
                if !property.signature.base.accepts_constant(&self.value) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with property type: {:?} (token: {})",
                        self.value.kind,
                        property.signature.base,
                        self.token.value()
                    ));
                }

                property
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for property"))
            }
            _ => Err(malformed_error!(
                "Invalid parent type for constant - {}",
                self.token.value()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{
            signatures::TypeSignature,
            tables::{Field, Param, Property},
            typesystem::{CilPrimitive, CilPrimitiveKind, ELEMENT_TYPE},
        },
        test::builders::{ConstantBuilder, FieldBuilder, ParamBuilder, PropertyBuilder},
    };
    use std::sync::Arc;

    // Helper function to create a simple i4 field
    fn create_i4_field(name: &str) -> Arc<Field> {
        FieldBuilder::simple_i4_field(name).build()
    }

    // Helper function to create a simple string field
    fn create_string_field(name: &str) -> Arc<Field> {
        FieldBuilder::simple_string_field(name).build()
    }

    // Helper function to create a simple boolean field
    fn create_boolean_field(name: &str) -> Arc<Field> {
        FieldBuilder::simple_boolean_field(name).build()
    }

    // Helper function to create a simple r4 field
    fn create_r4_field(name: &str) -> Arc<Field> {
        FieldBuilder::simple_r4_field(name).build()
    }

    // Helper function to create a simple object field
    fn create_object_field(name: &str) -> Arc<Field> {
        FieldBuilder::simple_object_field(name).build()
    }

    // Helper function to create a test property with a given type
    fn create_test_property(name: &str, property_type: TypeSignature) -> Arc<Property> {
        PropertyBuilder::simple_property(name, property_type).build()
    }

    // Helper function to create a test parameter
    fn create_test_param(name: &str) -> Arc<Param> {
        ParamBuilder::input_param(1, name).build()
    }

    #[test]
    fn test_apply_field_constant_success() {
        let field = create_i4_field("test_field");
        let constant = ConstantBuilder::field_i4_constant(1, field.clone(), 42).build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Expected successful application of constant to field"
        );

        // Verify the default value was set
        let default_value = field.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::I4);
        assert_eq!(default_value.as_i32(), Some(42));
    }

    #[test]
    fn test_apply_field_string_constant_success() {
        let field = create_string_field("test_field");
        let constant =
            ConstantBuilder::field_string_constant(1, field.clone(), "test_value").build();

        let result = constant.apply();
        if let Err(ref e) = result {
            println!("Error applying string constant: {}", e);
        }
        assert!(
            result.is_ok(),
            "Expected successful application of string constant to field"
        );

        // Verify the default value was set
        let default_value = field.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::String);
        assert_eq!(default_value.as_string(), Some("test_value".to_string()));
    }

    #[test]
    fn test_apply_field_constant_already_set() {
        let field = create_i4_field("test_field");

        // Set a default value first
        let _ = field.default.set(CilPrimitive::i4(100));

        // Try to apply another constant
        let constant = ConstantBuilder::field_i4_constant(1, field, 42).build();

        let result = constant.apply();
        assert!(
            result.is_err(),
            "Expected error when default value already set"
        );

        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Default value already set for field"));
    }

    #[test]
    fn test_apply_property_constant_success() {
        let property = create_test_property("test_property", TypeSignature::I4);
        let constant = ConstantBuilder::property_i4_constant(1, property.clone(), 123).build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Expected successful application of constant to property"
        );

        // Verify the default value was set
        let default_value = property.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::I4);
        assert_eq!(default_value.as_i32(), Some(123));
    }

    #[test]
    fn test_apply_property_constant_already_set() {
        let property = create_test_property("test_property", TypeSignature::I4);

        // Set a default value first
        let _ = property.default.set(CilPrimitive::i4(200));

        // Try to apply another constant
        let constant = ConstantBuilder::property_i4_constant(1, property, 123).build();

        let result = constant.apply();
        assert!(
            result.is_err(),
            "Expected error when default value already set"
        );

        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Default value already set for property"));
    }

    #[test]
    fn test_apply_param_constant_success() {
        let param = create_test_param("test_param");
        let constant = ConstantBuilder::param_i4_constant(1, param.clone(), 456).build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Expected successful application of constant to parameter"
        );

        // Verify the default value was set
        let default_value = param.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::I4);
        assert_eq!(default_value.as_i32(), Some(456));
    }

    #[test]
    fn test_apply_param_constant_already_set() {
        let param = create_test_param("test_param");

        // Set a default value first
        let _ = param.default.set(CilPrimitive::i4(300));

        // Try to apply another constant
        let constant = ConstantBuilder::param_i4_constant(1, param, 456).build();

        let result = constant.apply();
        assert!(
            result.is_err(),
            "Expected error when default value already set"
        );

        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Default value already set for param"));
    }

    #[test]
    fn test_apply_invalid_parent() {
        let constant = ConstantBuilder::invalid_parent_constant(1, 42).build();

        let result = constant.apply();
        assert!(result.is_err(), "Expected error for invalid parent type");

        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Invalid parent type for constant"));
    }

    #[test]
    fn test_multiple_constant_applications() {
        // Test applying constants to multiple fields of the same type
        let field1 = create_i4_field("field1");
        let field2 = create_i4_field("field2");

        let constant1 = ConstantBuilder::field_i4_constant(1, field1.clone(), 100).build();
        let constant2 = ConstantBuilder::field_i4_constant(2, field2.clone(), 200).build();

        // Both should succeed
        assert!(constant1.apply().is_ok());
        assert!(constant2.apply().is_ok());

        // Verify different values were set
        assert_eq!(field1.default.get().unwrap().as_i32(), Some(100));
        assert_eq!(field2.default.get().unwrap().as_i32(), Some(200));
    }

    #[test]
    fn test_edge_case_values() {
        // Test edge case values for different types

        // Test min/max i32 values
        let field_max = create_i4_field("field_max");
        let constant_max =
            ConstantBuilder::field_i4_constant(1, field_max.clone(), i32::MAX).build();
        assert!(constant_max.apply().is_ok());
        assert_eq!(field_max.default.get().unwrap().as_i32(), Some(i32::MAX));

        let field_min = create_i4_field("field_min");
        let constant_min =
            ConstantBuilder::field_i4_constant(2, field_min.clone(), i32::MIN).build();
        assert!(constant_min.apply().is_ok());
        assert_eq!(field_min.default.get().unwrap().as_i32(), Some(i32::MIN));

        // Test empty string
        let field_empty = create_string_field("field_empty");
        let constant_empty =
            ConstantBuilder::field_string_constant(3, field_empty.clone(), "").build();
        assert!(constant_empty.apply().is_ok());
        assert_eq!(
            field_empty.default.get().unwrap().as_string(),
            Some(String::new())
        );
    }

    #[test]
    fn test_apply_different_primitive_types() {
        // Test boolean constant
        let field_bool = create_boolean_field("field_bool");
        let constant_bool = ConstantBuilder::new(
            1,
            ELEMENT_TYPE::BOOLEAN,
            CilTypeReference::Field(field_bool.clone()),
            Arc::new(CilPrimitive::boolean(true)),
        )
        .build();

        let result = constant_bool.apply();
        assert!(result.is_ok());

        let default_value = field_bool.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::Boolean);
        if let crate::metadata::typesystem::CilPrimitiveData::Boolean(value) = &default_value.data {
            assert!(*value);
        } else {
            panic!("Expected Boolean primitive data");
        }

        // Test float constant
        let field_r4 = create_r4_field("field_r4");
        let constant_r4 = ConstantBuilder::new(
            2,
            ELEMENT_TYPE::R4,
            CilTypeReference::Field(field_r4.clone()),
            Arc::new(CilPrimitive::r4(std::f32::consts::PI)),
        )
        .build();

        let result = constant_r4.apply();
        assert!(result.is_ok());

        let default_value = field_r4.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::R4);
        if let crate::metadata::typesystem::CilPrimitiveData::R4(value) = &default_value.data {
            assert!((value - std::f32::consts::PI).abs() < f32::EPSILON);
        } else {
            panic!("Expected R4 primitive data");
        }
    }

    #[test]
    fn test_apply_null_constant() {
        let field = create_object_field("field_object");
        let constant = ConstantBuilder::new(
            1,
            ELEMENT_TYPE::CLASS,
            CilTypeReference::Field(field.clone()),
            Arc::new(CilPrimitive::null()),
        )
        .build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Null constants should be applicable to reference types"
        );

        let default_value = field.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::Null);
    }
}
