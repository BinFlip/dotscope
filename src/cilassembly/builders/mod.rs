//! High-level builders for common .NET patterns.
//!
//! This module provides high-level builder APIs that compose the existing low-level
//! infrastructure to create common .NET constructs with fluent, ergonomic interfaces.
//!
//! # Architecture
//!
//! The builders follow a layered composition approach:
//! - **Layer 1**: High-level builders (MethodBuilder, ClassBuilder, etc.)
//! - **Layer 2**: Method body builders (MethodBodyBuilder)
//! - **Layer 3**: Low-level components (InstructionAssembler, MethodDefBuilder, etc.)
//!
//! This design maximizes reuse of existing tested components while providing
//! convenient high-level APIs for common scenarios.
//!
//! # Examples
//!
//! ## Simple Class Creation
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! # fn example() -> dotscope::Result<()> {
//! # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//! // Create a complete class with properties and methods
//! let class_token = ClassBuilder::new("Person")
//!     .public()
//!     .namespace("MyApp.Models")
//!     .auto_property("Name", TypeSignature::String)
//!     .auto_property("Age", TypeSignature::I4)
//!     .method(|_m| MethodBuilder::new("GetInfo")
//!         .public()
//!         .returns(TypeSignature::String)
//!         .implementation(|body| {
//!             body.implementation(|asm| {
//!                 asm.ldstr(Token::new(0x70000001))? // "Person info"
//!                    .ret()?;
//!                 Ok(())
//!             })
//!         }))
//!     .default_constructor()
//!     .build(&mut context)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Simple Method Creation
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! # fn example() -> dotscope::Result<()> {
//! # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//! // Create a simple addition method
//! let method_token = MethodBuilder::new("Add")
//!     .public()
//!     .static_method()
//!     .parameter("a", TypeSignature::I4)
//!     .parameter("b", TypeSignature::I4)
//!     .returns(TypeSignature::I4)
//!     .implementation(|body| {
//!         body.implementation(|asm| {
//!             asm.ldarg_0()?
//!                .ldarg_1()?
//!                .add()?
//!                .ret()?;
//!             Ok(())
//!         })
//!     })
//!     .build(&mut context)?;
//! # Ok(())
//! # }
//! ```

mod class;
mod enums;
mod event;
mod interface;
mod method;
mod method_body;
mod property;

// Re-export the main builders for convenience
pub use class::ClassBuilder;
pub use enums::EnumBuilder;
pub use event::EventBuilder;
pub use interface::InterfaceBuilder;
pub use method::MethodBuilder;
pub use method_body::MethodBodyBuilder;
pub use property::PropertyBuilder;
