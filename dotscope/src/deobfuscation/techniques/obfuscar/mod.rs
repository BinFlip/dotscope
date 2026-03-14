//! Obfuscar-specific deobfuscation techniques.
//!
//! Obfuscar is a renaming-focused obfuscator with XOR-based string hiding as its
//! only code-transforming protection. The string hiding injects a
//! `<PrivateImplementationDetails>{GUID}` helper type with per-string accessor
//! methods that are decrypted via emulation.

mod strings;

pub use strings::ObfuscarStrings;
