use crate::{
    file::parser::Parser,
    metadata::{
        signatures::{
            SignatureArray, SignatureField, SignatureLocalVariable, SignatureLocalVariables,
            SignatureMethod, SignatureMethodSpec, SignatureParameter, SignaturePointer,
            SignatureProperty, SignatureSzArray, SignatureTypeSpec, TypeSignature,
        },
        token::Token,
        typesystem::{ArrayDimensions, ELEMENT_TYPE},
    },
    Error::RecursionLimit,
    Result,
};

/// Maximum recursion depth for signature parsing
const MAX_RECURSION_DEPTH: usize = 50;

/// Signature parser that handles all signature types in ECMA-335
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::metadata::signatures::SignatureParser;
/// let data = &[0x20, 0x01, 0x01, 0x0E];
/// let mut parser = SignatureParser::new(data);
/// let sig = parser.parse_method_signature().unwrap();
/// assert_eq!(sig.params.len(), 1);
/// ```
///
/// ## Notes:
/// - Besides ECMA-335, it's also worth looking at <https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/profiling/davbr-blog-archive/samples/sigparse.cpp>
/// - If you're using the `SignatureParser` directly, and not via one of its wrapper functions that are exposed via the signature module),
///   make sure to not re-use your parser instance for multiple signatures.
pub struct SignatureParser<'a> {
    parser: Parser<'a>,
    depth: usize,
}

impl<'a> SignatureParser<'a> {
    /// Create a new `SignatureParser` from a byte slice
    ///
    /// ## Arguments
    /// * 'data' - The byte slice to read from
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        SignatureParser {
            parser: Parser::new(data),
            depth: 0,
        }
    }

    /// Parse a single type from the signature blob
    fn parse_type(&mut self) -> Result<TypeSignature> {
        self.depth += 1;
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(RecursionLimit(MAX_RECURSION_DEPTH));
        }

        let current_byte = self.parser.read_le::<u8>()?;
        match current_byte {
            ELEMENT_TYPE::VOID => Ok(TypeSignature::Void),
            ELEMENT_TYPE::BOOLEAN => Ok(TypeSignature::Boolean),
            ELEMENT_TYPE::CHAR => Ok(TypeSignature::Char),
            ELEMENT_TYPE::I1 => Ok(TypeSignature::I1),
            ELEMENT_TYPE::U1 => Ok(TypeSignature::U1),
            ELEMENT_TYPE::I2 => Ok(TypeSignature::I2),
            ELEMENT_TYPE::U2 => Ok(TypeSignature::U2),
            ELEMENT_TYPE::I4 => Ok(TypeSignature::I4),
            ELEMENT_TYPE::U4 => Ok(TypeSignature::U4),
            ELEMENT_TYPE::I8 => Ok(TypeSignature::I8),
            ELEMENT_TYPE::U8 => Ok(TypeSignature::U8),
            ELEMENT_TYPE::R4 => Ok(TypeSignature::R4),
            ELEMENT_TYPE::R8 => Ok(TypeSignature::R8),
            ELEMENT_TYPE::STRING => Ok(TypeSignature::String),
            ELEMENT_TYPE::PTR => Ok(TypeSignature::Ptr(SignaturePointer {
                modifiers: self.parse_custom_mods()?,
                base: Box::new(self.parse_type()?),
            })),
            ELEMENT_TYPE::BYREF => Ok(TypeSignature::ByRef(Box::new(self.parse_type()?))),
            ELEMENT_TYPE::VALUETYPE => Ok(TypeSignature::ValueType(
                self.parser.read_compressed_token()?,
            )),
            ELEMENT_TYPE::CLASS => Ok(TypeSignature::Class(self.parser.read_compressed_token()?)),
            ELEMENT_TYPE::VAR => Ok(TypeSignature::GenericParamType(
                self.parser.read_compressed_uint()?,
            )),
            ELEMENT_TYPE::ARRAY => {
                let elem_type = self.parse_type()?;
                let rank = self.parser.read_compressed_uint()?;

                let num_sizes = self.parser.read_compressed_uint()?;
                let mut dimensions: Vec<ArrayDimensions> = Vec::with_capacity(num_sizes as usize);
                for _ in 0..num_sizes {
                    dimensions.push(ArrayDimensions {
                        size: Some(self.parser.read_compressed_uint()?),
                        lower_bound: None,
                    });
                }

                let num_lo_bounds = self.parser.read_compressed_uint()?;
                for i in 0..num_lo_bounds {
                    if let Some(dimension) = dimensions.get_mut(i as usize) {
                        dimension.lower_bound = Some(self.parser.read_compressed_uint()?);
                    }
                }

                Ok(TypeSignature::Array(SignatureArray {
                    base: Box::new(elem_type),
                    rank,
                    dimensions,
                }))
            }
            ELEMENT_TYPE::GENERICINST => {
                let peek_byte = self.parser.peek_byte()?;
                if peek_byte != 0x12 && peek_byte != 0x11 {
                    return Err(malformed_error!(
                        "GENERICINST - Next byte is not TYPE_CLASS or TYPE_VALUE - {}",
                        peek_byte
                    ));
                }

                let base_type = self.parse_type()?;
                let arg_count = self.parser.read_compressed_uint()?;

                let mut type_args = Vec::with_capacity(arg_count as usize);
                for _ in 0..arg_count {
                    type_args.push(self.parse_type()?);
                }

                Ok(TypeSignature::GenericInst(Box::new(base_type), type_args))
            }
            ELEMENT_TYPE::TYPEDBYREF => Ok(TypeSignature::TypedByRef),
            ELEMENT_TYPE::I => Ok(TypeSignature::I),
            ELEMENT_TYPE::U => Ok(TypeSignature::U),
            ELEMENT_TYPE::FNPTR => Ok(TypeSignature::FnPtr(Box::new(
                self.parse_method_signature()?,
            ))),
            ELEMENT_TYPE::OBJECT => Ok(TypeSignature::Object),
            ELEMENT_TYPE::SZARRAY => Ok(TypeSignature::SzArray(SignatureSzArray {
                modifiers: self.parse_custom_mods()?,
                base: Box::new(self.parse_type()?),
            })),
            ELEMENT_TYPE::MVAR => Ok(TypeSignature::GenericParamMethod(
                self.parser.read_compressed_uint()?,
            )),
            ELEMENT_TYPE::CMOD_REQD => {
                Ok(TypeSignature::ModifiedRequired(self.parse_custom_mods()?))
            }
            ELEMENT_TYPE::CMOD_OPT => {
                Ok(TypeSignature::ModifiedOptional(self.parse_custom_mods()?))
            }
            ELEMENT_TYPE::INTERNAL => Ok(TypeSignature::Internal),
            ELEMENT_TYPE::MODIFIER => Ok(TypeSignature::Modifier),
            ELEMENT_TYPE::SENTINEL => Ok(TypeSignature::Sentinel),
            ELEMENT_TYPE::PINNED => Ok(TypeSignature::Pinned(Box::new(self.parse_type()?))),
            _ => Err(malformed_error!(
                "Unsupported ELEMENT_TYPE - {}",
                current_byte
            )),
        }
    }

    /// Parse custom modifiers (`CMOD_OPT` or `CMOD_REQD`)
    fn parse_custom_mods(&mut self) -> Result<Vec<Token>> {
        let mut mods = Vec::new();

        while self.parser.has_more_data() {
            let next_byte = self.parser.peek_byte()?;
            if next_byte != 0x20 && next_byte != 0x1F {
                break;
            }

            self.parser.advance()?;

            mods.push(self.parser.read_compressed_token()?);
        }

        Ok(mods)
    }

    /// Parse a parameter including custom modifiers (`return_type` counts as parameter)
    fn parse_param(&mut self) -> Result<SignatureParameter> {
        let custom_mods = self.parse_custom_mods()?;

        let mut by_ref = false;
        if self.parser.peek_byte()? == 0x10 {
            self.parser.advance()?;
            by_ref = true;
        }

        Ok(SignatureParameter {
            modifiers: custom_mods,
            by_ref,
            base: self.parse_type()?,
        })
    }

    /// Parse a method signature from the blob - `MethodDefSig`, `MethodRefSig`, `StandAloneMethodSig`
    ///
    /// # Errors
    /// Returns an error if the signature data is malformed or if reading beyond the buffer bounds.
    pub fn parse_method_signature(&mut self) -> Result<SignatureMethod> {
        let convention_byte = self.parser.read_le::<u8>()?;

        let mut method = SignatureMethod {
            has_this: convention_byte & 0x20 != 0,
            explicit_this: convention_byte & 0x40 != 0,
            default: convention_byte == 0,
            vararg: convention_byte & 0x5 != 0,
            cdecl: convention_byte & 0x1 != 0,
            stdcall: convention_byte & 0x2 != 0,
            thiscall: convention_byte & 0x3 != 0,
            fastcall: convention_byte & 0x4 != 0,
            param_count_generic: if convention_byte & 0x10 != 0 {
                self.parser.read_compressed_uint()?
            } else {
                0
            },
            param_count: self.parser.read_compressed_uint()?,
            return_type: self.parse_param()?,
            params: Vec::new(),
            varargs: Vec::new(),
        };

        for _ in 0..method.param_count {
            if self.parser.peek_byte()? == 0x41 {
                // 0x41 == SENTINEL, indicates that Param is over, and next is the vararg param list for the remaining elements

                self.parser.advance()?;
                break;
            }

            method.params.push(self.parse_param()?);
        }

        if method.vararg && method.params.len() < method.param_count as usize {
            for _ in method.params.len()..method.param_count as usize {
                method.varargs.push(self.parse_param()?);
            }
        }

        Ok(method)
    }

    /// Parse a field signature from the blob (II.23.2.4)
    ///
    /// # Errors
    /// Returns an error if the signature header is invalid or if the field type cannot be parsed.
    pub fn parse_field_signature(&mut self) -> Result<SignatureField> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != 0x06 {
            // 0x06 == FIELD
            return Err(malformed_error!(
                "SignatureField - invalid start - {}",
                head_byte
            ));
        }

        let custom_mods = self.parse_custom_mods()?;
        let type_sig = self.parse_type()?;

        Ok(SignatureField {
            modifiers: custom_mods,
            base: type_sig,
        })
    }

    /// Parse a property signature from the blob (II.23.2.5)
    ///
    /// # Errors
    /// Returns an error if the property signature header is invalid or if the property type cannot be parsed.
    pub fn parse_property_signature(&mut self) -> Result<SignatureProperty> {
        let head_byte = self.parser.read_le::<u8>()?;
        if (head_byte & 0x08) == 0 {
            return Err(malformed_error!(
                "SignatureProperty - invalid start - {}",
                head_byte
            ));
        }

        let has_this = (head_byte & 0x20) != 0;

        let param_count = self.parser.read_compressed_uint()?;
        let custom_mods = self.parse_custom_mods()?;
        let type_sig = self.parse_type()?;

        let mut params = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            params.push(self.parse_param()?);
        }

        Ok(SignatureProperty {
            has_this,
            modifiers: custom_mods,
            base: type_sig,
            params,
        })
    }

    /// Parse a local variable signature from the blob (II.23.2.6)
    ///
    /// # Errors
    /// Returns an error if the local variable signature header is invalid or if variable types cannot be parsed.
    pub fn parse_local_var_signature(&mut self) -> Result<SignatureLocalVariables> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != 0x07 {
            return Err(malformed_error!(
                "SignatureLocalVar - invalid start - {}",
                head_byte
            ));
        }

        let count = self.parser.read_compressed_uint()?;

        let mut locals = Vec::with_capacity(count as usize);
        for _ in 0..count {
            // Slighly different, not all custom_mods are following each other, but rather costom_mod -> contstraint -> custom_mod -> ...

            // TYPED_BY_REF
            if self.parser.peek_byte()? == 0x16 {
                locals.push(SignatureLocalVariable {
                    modifiers: Vec::new(),
                    is_byref: false,
                    is_pinned: false,
                    base: TypeSignature::TypedByRef,
                });
                self.parser.advance()?;

                continue;
            }

            let mut custom_mods = Vec::new();
            let mut pinned = false;

            while self.parser.has_more_data() {
                match self.parser.peek_byte()? {
                    0x1F | 0x20 => {
                        self.parser.advance()?;
                        custom_mods.push(self.parser.read_compressed_token()?);
                    }
                    0x45 => {
                        // Only 'Constraint' that is supported at the moment - PINNED - II.23.2.9
                        // ToDo - this seems to be for each custom modifier and not just per local variable? Might be wrong currently
                        //        and should be stored together with the custom modifier

                        self.parser.advance()?;
                        pinned = true;
                    }
                    _ => break,
                }
            }

            let by_ref = if self.parser.peek_byte()? == 0x10 {
                self.parser.advance()?;
                true
            } else {
                false
            };

            let type_sig = self.parse_type()?;

            locals.push(SignatureLocalVariable {
                modifiers: custom_mods,
                is_byref: by_ref,
                is_pinned: pinned,
                base: type_sig,
            });
        }

        Ok(SignatureLocalVariables { locals })
    }

    /// Parse a type specification signature from the blob (II.23.2.14)
    ///
    /// # Errors
    /// Returns an error if the type specification cannot be parsed.
    pub fn parse_type_spec_signature(&mut self) -> Result<SignatureTypeSpec> {
        let type_sig = self.parse_type()?;
        Ok(SignatureTypeSpec { base: type_sig })
    }

    /// Parse a method specification signature from the blob (II.23.2.15)
    ///
    /// # Errors
    /// Returns an error if the method specification header is invalid or if the type arguments cannot be parsed.
    pub fn parse_method_spec_signature(&mut self) -> Result<SignatureMethodSpec> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != 0x0A {
            return Err(malformed_error!(
                "SignatureMethodSpec - invalid start - {}",
                head_byte
            ));
        }

        let arg_count = self.parser.read_compressed_uint()?;
        let mut generic_args = Vec::with_capacity(arg_count as usize);
        for _ in 0..arg_count {
            generic_args.push(self.parse_type()?);
        }

        Ok(SignatureMethodSpec { generic_args })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_primitive_types() {
        let test_cases = [
            (vec![0x01], TypeSignature::Void),
            (vec![0x02], TypeSignature::Boolean),
            (vec![0x03], TypeSignature::Char),
            (vec![0x04], TypeSignature::I1),
            (vec![0x05], TypeSignature::U1),
            (vec![0x06], TypeSignature::I2),
            (vec![0x07], TypeSignature::U2),
            (vec![0x08], TypeSignature::I4),
            (vec![0x09], TypeSignature::U4),
            (vec![0x0A], TypeSignature::I8),
            (vec![0x0B], TypeSignature::U8),
            (vec![0x0C], TypeSignature::R4),
            (vec![0x0D], TypeSignature::R8),
            (vec![0x0E], TypeSignature::String),
            (vec![0x1C], TypeSignature::Object),
            (vec![0x18], TypeSignature::I),
            (vec![0x19], TypeSignature::U),
        ];

        for (bytes, expected_type) in test_cases {
            let mut parser = SignatureParser::new(&bytes);
            let result = parser.parse_type().unwrap();
            assert_eq!(result, expected_type);
        }
    }

    #[test]
    fn test_parse_class_and_valuetype() {
        // Class type: Class token 0x10 in TypeRef
        let mut parser = SignatureParser::new(&[0x12, 0x42]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::Class(Token::new(0x1B000010))
        );

        // Value type: Token 0xD in TypeRef
        let mut parser = SignatureParser::new(&[0x11, 0x35]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::ValueType(Token::new(0x100000D))
        );

        // Generic parameter: Index 3
        let mut parser = SignatureParser::new(&[0x13, 0x03]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::GenericParamType(0x03)
        );
    }

    #[test]
    fn test_parse_arrays() {
        // SzArray of Int32 (int[])
        let mut parser = SignatureParser::new(&[0x1D, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::SzArray(_)));
        if let TypeSignature::SzArray(inner) = result {
            assert_eq!(*inner.base, TypeSignature::I4);
        }

        // Multi-dimensional array int[,] with rank 2, no sizes, no bounds
        let mut parser = SignatureParser::new(&[
            0x14, // ARRAY
            0x08, // I4 (element type)
            0x02, // rank 2
            0x00, // num_sizes 0
            0x00, // num_lo_bounds 0
        ]);

        let result = parser.parse_type().unwrap();
        assert!(matches!(result, TypeSignature::Array(_)));
        if let TypeSignature::Array(array) = result {
            assert_eq!(*array.base, TypeSignature::I4);
            assert_eq!(array.rank, 2);
            assert_eq!(array.dimensions.len(), 0)
        }

        // Multi-dimensional array int[2,3] with rank 2, with sizes
        let mut parser = SignatureParser::new(&[
            0x14, // ARRAY
            0x08, // I4 (element type)
            0x02, // rank 2
            0x02, // num_sizes 2
            0x02, // size 2
            0x03, // size 3
            0x00, // num_lo_bounds 0
        ]);

        let result = parser.parse_type().unwrap();
        assert!(matches!(result, TypeSignature::Array(_)));
        if let TypeSignature::Array(array) = result {
            assert_eq!(*array.base, TypeSignature::I4);
            assert_eq!(array.rank, 2);
            assert_eq!(array.dimensions.len(), 2);
            assert_eq!(array.dimensions[0].lower_bound, None);
            assert_eq!(array.dimensions[0].size, Some(2));
            assert_eq!(array.dimensions[1].lower_bound, None);
            assert_eq!(array.dimensions[1].size, Some(3));
        }
    }

    #[test]
    fn test_parse_pointers_and_byrefs() {
        // Pointer to Int32 (int*)
        let mut parser = SignatureParser::new(&[0x0F, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::Ptr(_)));
        if let TypeSignature::Ptr(inner) = result {
            assert_eq!(*inner.base, TypeSignature::I4);
        }

        // ByRef to Int32 (ref int)
        let mut parser = SignatureParser::new(&[0x10, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::ByRef(_)));
        if let TypeSignature::ByRef(inner) = result {
            assert_eq!(*inner, TypeSignature::I4);
        }
    }

    #[test]
    fn test_parse_generic_instance() {
        // Generic instance List<int>
        // Assume List is token 0x1B
        let mut parser = SignatureParser::new(&[
            0x15, // GENERICINST
            0x12, 0x49, // Class token for List
            0x01, // arg count
            0x08, // I4 type arg
        ]);

        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::GenericInst(_, _)));
        if let TypeSignature::GenericInst(class, args) = result {
            assert!(matches!(*class, TypeSignature::Class(_)));
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], TypeSignature::I4);
        }

        // Generic instance Dictionary<string, int>
        // Assume Dictionary is token 0x2A
        let mut parser = SignatureParser::new(&[
            0x15, // GENERICINST
            0x12, 0x2A, // Class token for Dictionary
            0x02, // 2 type args
            0x0E, // String type arg
            0x08, // I4 type arg
        ]);

        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::GenericInst(_, _)));
        if let TypeSignature::GenericInst(class, args) = result {
            assert!(matches!(*class, TypeSignature::Class(_)));
            assert_eq!(args.len(), 2);
            assert_eq!(args[0], TypeSignature::String);
            assert_eq!(args[1], TypeSignature::I4);
        }
    }

    #[test]
    fn test_parse_custom_mods() {
        // Optional modifier (modopt) followed by required modifier (modreq)
        let mut parser = SignatureParser::new(&[
            0x20, 0x42, // CMOD_OPT, token 0x42
            0x1F, 0x49, // CMOD_REQD, token 0x49
            0x08, // I4 (to test we can still parse after the modifiers)
        ]);

        let mods = parser.parse_custom_mods().unwrap();
        assert_eq!(mods, vec![Token::new(0x1B000010), Token::new(0x01000012)]);

        // Verify we can still parse the type after the modifiers
        let type_sig = parser.parse_type().unwrap();
        assert_eq!(type_sig, TypeSignature::I4);

        // Test empty modifiers
        let mut parser = SignatureParser::new(&[0x08]); // Just I4, no mods
        let mods = parser.parse_custom_mods().unwrap();
        assert!(mods.is_empty());
    }

    #[test]
    fn test_complex_signature() {
        // A complex method signature:
        // Dictionary<List<int>, string[]> Method<T>(ref T arg1, List<int>[] arg2)
        let mut parser = SignatureParser::new(&[
            0x30, // HASTHIS | GENERIC
            0x01, // 1 generic parameter
            0x02, // 2 parameters
            // Return type: Dictionary<List<int>, string[]>
            0x15, // GENERICINST
            0x12, 0x2A, // Class token for Dictionary
            0x02, // arg count
            // First type arg: List<int>
            0x15, // GENERICINST
            0x12, 0x49, // Class token for List
            0x01, // arg count
            0x08, // I4
            // Second type arg: string[]
            0x1D, // SZARRAY
            0x0E, // String
            // First parameter: ref T
            0x10, // BYREF
            0x13, 0x00, // GenericParam(0)
            // Second parameter: List<int>[]
            0x1D, // SZARRAY
            0x15, // GENERICINST
            0x12, 0x42, // Class token for List
            0x01, // arg count
            0x08, // I4
        ]);

        let result = parser.parse_method_signature().unwrap();

        // Test method general properties
        assert!(result.has_this);
        assert_eq!(result.param_count_generic, 1);
        assert_eq!(result.params.len(), 2);

        // Test return type (Dictionary<List<int>, string[]>)
        assert!(matches!(
            result.return_type.base,
            TypeSignature::GenericInst(_, _)
        ));

        // Test first parameter (ref T)
        assert!(result.params[0].by_ref);
        assert_eq!(result.params[0].base, TypeSignature::GenericParamType(0));

        // Test second parameter (List<int>[])
        assert!(!result.params[1].by_ref);
        assert!(matches!(result.params[1].base, TypeSignature::SzArray(_)));
    }

    #[test]
    fn test_error_handling() {
        // Test invalid method signature format
        let mut parser = SignatureParser::new(&[0xFF, 0x01]);
        assert!(matches!(
            parser.parse_method_signature(),
            Err(crate::Error::OutOfBounds)
        ));

        // Test invalid field signature format
        let mut parser = SignatureParser::new(&[0x07, 0x08]); // Should be 0x06 for FIELD
        assert!(parser.parse_field_signature().is_err());
    }
}
