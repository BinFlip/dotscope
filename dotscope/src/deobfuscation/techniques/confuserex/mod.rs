//! ConfuserEx-specific deobfuscation techniques.
//!
//! This module provides technique implementations for detecting and reversing
//! protections applied by ConfuserEx, a popular open-source .NET obfuscator.
//! Each technique targets a specific protection layer and implements the
//! unified [`Technique`](super::Technique) trait.
//!
//! # Technique Overview
//!
//! | Technique | Kind | Category | Description |
//! |-----------|------|----------|-------------|
//! | [`ConfuserExMarker`] | Byte | Metadata | Removes ConfuserEx marker attributes |
//! | [`ConfuserExMetadata`] | Byte | Metadata | Patches invalid 0x7fff metadata |
//! | [`ConfuserExAntiTamper`] | Byte | Protection | Decrypts encrypted method bodies |
//! | [`ConfuserExResources`] | Byte | Protection | Decrypts embedded resources |
//! | [`ConfuserExNativeHelpers`] | Byte | Protection | Converts native x86 helpers to CIL |
//! | [`ConfuserExConstants`] | SSA | Value | Decrypts constants via emulation |
//! | [`ConfuserExReferenceProxy`] | SSA | Call | Inlines proxy call forwarders |
//! | [`ConfuserExAntiDebug`] | SSA | Neutralization | Neutralizes anti-debug checks |
//! | [`ConfuserExAntiDump`] | SSA | Neutralization | Neutralizes anti-dump code |

mod constants;
mod debug;
mod dump;
mod helpers;
mod hooks;
mod marker;
mod metadata;
mod natives;
mod proxy;
mod resources;
mod statemachine;
mod tamper;

pub use constants::ConfuserExConstants;
pub use debug::ConfuserExAntiDebug;
pub use dump::ConfuserExAntiDump;
pub use marker::ConfuserExMarker;
pub use metadata::ConfuserExMetadata;
pub use natives::ConfuserExNativeHelpers;
pub use proxy::ConfuserExReferenceProxy;
pub use resources::ConfuserExResources;
pub use tamper::ConfuserExAntiTamper;
