//! Hook system for method interception during emulation.
//!
//! This module provides the hook system for intercepting method calls during .NET
//! emulation. Hooks support:
//!
//! - **Multiple matching criteria**: Match by name, signature types, or runtime data
//! - **Pre/post execution**: Run code before and/or after the original method
//! - **Bypass capability**: Pre-hooks can skip the original method entirely
//! - **Closure-based handlers**: Less boilerplate than trait implementations
//!
//! # Overview
//!
//! The hook system provides flexible method interception with multiple matching
//! criteria:
//!
//! - **Name matching**: Match by namespace, type name, and/or method name
//! - **Signature matching**: Match by parameter types and return type
//! - **Internal method matching**: Match only methods defined in the target assembly
//! - **Runtime matching**: Match by inspecting actual argument values
//!
//! # Organization
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`types`] | Core types: priorities, results, context |
//! | [`matcher`] | Matcher trait and implementations |
//! | [`hook`] | The [`Hook`] builder and executor |
//! | [`manager`] | [`HookManager`] for hook registration and lookup |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      HookManager                            │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │  hooks: Vec<Hook>  (sorted by priority)             │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! │                          │                                  │
//! │                          ▼                                  │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │  find_matching(context) -> Option<&Hook>            │   │
//! │  │  execute_pre(hook, context) -> PreHookResult        │   │
//! │  │  execute_post(hook, context, result) -> PostResult  │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Hook Execution Flow
//!
//! ```text
//! Method call intercepted
//!         │
//!         ▼
//! ┌───────────────────┐
//! │  Find matching    │───► No match ───► Execute original
//! │  hook             │
//! └───────────────────┘
//!         │ Match found
//!         ▼
//! ┌───────────────────┐
//! │  Execute pre_hook │───► Bypass(value) ───► Return value
//! └───────────────────┘
//!         │ Continue
//!         ▼
//! ┌───────────────────┐
//! │  Execute original │
//! │  method           │
//! └───────────────────┘
//!         │
//!         ▼
//! ┌───────────────────┐
//! │  Execute post_hook│───► Can modify result
//! └───────────────────┘
//!         │
//!         ▼
//!    Return result
//! ```
//!
//! # Examples
//!
//! ## Simple Name-Based Hook
//!
//! ```rust,ignore
//! use dotscope::emulation::{Hook, HookManager, PreHookResult};
//!
//! let mut manager = HookManager::new();
//!
//! manager.register(
//!     Hook::new("log-assembly-load")
//!         .match_name("System.Reflection", "Assembly", "Load")
//!         .pre(|ctx, thread| {
//!             println!("Assembly.Load called!");
//!             PreHookResult::Continue
//!         })
//! );
//! ```
//!
//! ## Signature-Based Hook with Bypass
//!
//! ```rust,ignore
//! use dotscope::emulation::{Hook, HookManager, PreHookResult};
//! use dotscope::metadata::typesystem::CilFlavor;
//!
//! let mut manager = HookManager::new();
//!
//! // Intercept byte[] -> byte[] methods that look like LZMA
//! manager.register(
//!     Hook::new("confuserex-lzma")
//!         .match_internal_method()
//!         .match_signature(vec![CilFlavor::Array { .. }], Some(CilFlavor::Array { .. }))
//!         .match_runtime("lzma-header", |ctx, thread| {
//!             // Check if input looks like LZMA data
//!             is_confuserex_lzma_header(ctx, thread)
//!         })
//!         .pre(|ctx, thread| {
//!             let decompressed = decompress_lzma(ctx, thread);
//!             PreHookResult::Bypass(Some(decompressed))
//!         })
//! );
//! ```
//!
//! # Use Cases
//!
//! ## Deobfuscation
//!
//! Hooks are particularly useful for deobfuscation scenarios:
//!
//! - **LZMA decompression**: Bypass embedded LZMA decompressors with native code
//! - **String decryption**: Capture arguments to custom decryption methods
//! - **Control flow recovery**: Monitor dispatcher state variable updates
//!
//! ## BCL Method Emulation
//!
//! Hooks provide implementations for .NET Base Class Library methods:
//!
//! - **String operations**: `String.Concat`, `String.Substring`, etc.
//! - **Encoding**: `Encoding.GetBytes`, `Encoding.GetString`
//! - **Cryptography**: MD5, SHA1, SHA256 hash computations
//! - **Array operations**: `Array.Copy`, `Buffer.BlockCopy`
//!
//! ## Malware Analysis
//!
//! For malware analysis, hooks can:
//!
//! - Capture encryption keys passed to crypto methods
//! - Log all method calls matching certain patterns
//! - Replace dangerous operations with safe alternatives

mod core;
mod manager;
mod matcher;
mod types;

pub use core::Hook;
pub use manager::HookManager;
pub use matcher::{
    HookMatcher, InternalMethodMatcher, NameMatcher, NativeMethodMatcher, RuntimeMatcher,
    SignatureMatcher,
};
pub use types::{
    HookContext, HookOutcome, HookPriority, PostHookFn, PostHookResult, PreHookFn, PreHookResult,
};
