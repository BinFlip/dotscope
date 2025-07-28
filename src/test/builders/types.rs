//! Type builders for creating mock CilType and related type instances
//!
//! This module provides builders for creating CilType and ExportedType instances
//! with various characteristics including inheritance, interfaces, and value types.

use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        tables::{ExportedType, ExportedTypeRc},
        token::Token,
        typesystem::{CilFlavor, CilType, CilTypeRc, CilTypeReference},
    },
    test::FileBuilder,
};

/// Builder for creating mock CilType instances with various characteristics
pub struct CilTypeBuilder {
    token: Token,
    namespace: String,
    name: String,
    external: Option<CilTypeReference>,
    flavor: Option<CilFlavor>,
    flags: u32,
}

impl CilTypeBuilder {
    pub fn new() -> Self {
        Self {
            token: Token::new(0x02000001),
            namespace: "Test".to_string(),
            name: "TestType".to_string(),
            external: None,
            flavor: Some(CilFlavor::Class),
            flags: 0,
        }
    }

    pub fn with_token(mut self, token: Token) -> Self {
        self.token = token;
        self
    }

    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = namespace.to_string();
        self
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn with_external(mut self, external: CilTypeReference) -> Self {
        self.external = Some(external);
        self
    }

    pub fn with_flavor(mut self, flavor: CilFlavor) -> Self {
        self.flavor = Some(flavor);
        self
    }

    /// Create a simple class type
    pub fn simple_class(namespace: &str, name: &str) -> Self {
        Self::new()
            .with_namespace(namespace)
            .with_name(name)
            .with_flavor(CilFlavor::Class)
    }

    /// Create an interface type
    pub fn interface(namespace: &str, name: &str) -> Self {
        Self::new()
            .with_namespace(namespace)
            .with_name(name)
            .with_flavor(CilFlavor::Interface)
    }

    /// Create a value type/struct
    pub fn value_type(namespace: &str, name: &str) -> Self {
        Self::new()
            .with_namespace(namespace)
            .with_name(name)
            .with_flavor(CilFlavor::ValueType)
    }

    /// Create an enum type
    pub fn enum_type(namespace: &str, name: &str) -> Self {
        Self::new()
            .with_namespace(namespace)
            .with_name(name)
            .with_flavor(CilFlavor::ValueType) // Enums are value types in .NET
    }

    pub fn build(self) -> CilTypeRc {
        Arc::new(CilType::new(
            self.token,
            self.namespace,
            self.name,
            self.external,
            None, // base type
            self.flags,
            Arc::new(boxcar::Vec::new()), // fields
            Arc::new(boxcar::Vec::new()), // methods
            self.flavor,
        ))
    }
}

impl Default for CilTypeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to create an ExportedTypeRc
pub fn create_exportedtype(dummy_type: CilTypeRc) -> ExportedTypeRc {
    let implementation_lock = OnceLock::new();
    implementation_lock
        .set(CilTypeReference::File(
            FileBuilder::new()
                .with_rid(1)
                .with_name("export_test")
                .build(),
        ))
        .ok();

    Arc::new(ExportedType {
        rid: 1,
        token: Token::new(0x27000001),
        offset: 0,
        flags: 0,
        type_def_id: dummy_type.token.0,
        name: "ExportedType".to_string(),
        namespace: Some("Test.Namespace".to_string()),
        implementation: implementation_lock,
        custom_attributes: Arc::new(boxcar::Vec::new()),
    })
}
