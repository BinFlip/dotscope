//! ConfuserEx resource decryption via emulation.
//!
//! This module provides resource protection decryption by:
//! 1. Finding the resource initializer method via candidate detection
//! 2. Emulating it with stubs for Assembly.Load to capture decrypted assemblies
//! 3. Extracting resources from the captured hidden assemblies
//! 4. Inserting those resources back into the original assembly
//!
//! # ConfuserEx Resource Protection
//!
//! ConfuserEx resource protection works as follows:
//! 1. All `EmbeddedResource` entries are moved to a hidden temporary assembly
//! 2. The hidden assembly is compressed with LZMA
//! 3. Encrypted with a block cipher (XOR in Normal mode)
//! 4. Stored in a FieldRVA (static field with raw data)
//! 5. A runtime stub registers an AssemblyResolve handler that:
//!    - Reads the encrypted data from the field
//!    - Decrypts using XOR with a key derived from xorshift
//!    - Decompresses with LZMA
//!    - Returns the hidden assembly via Assembly.Load
//!
//! By emulating this runtime stub and capturing Assembly.Load calls,
//! we can extract the hidden assemblies and recover the original resources.
//!
//! # Deobfuscation Process
//!
//! 1. Emulate the resource decryptor to capture hidden assembly bytes
//! 2. Load hidden assemblies as CilObjects
//! 3. Extract ManifestResource entries from hidden assemblies
//! 4. Insert resources back into the original assembly using CilAssembly
//! 5. Return the modified assembly with resources restored

use std::sync::Arc;

use crate::{
    assembly::Operand,
    cilassembly::{CilAssembly, GeneratorConfig},
    deobfuscation::{
        changes::EventLog,
        detection::{DetectionEvidence, DetectionScore},
        obfuscators::confuserex::{
            candidates::{find_candidates, ProtectionType},
            findings::ConfuserExFindings,
            hooks::create_lzma_hook,
        },
    },
    emulation::{EmulationOutcome, ProcessBuilder},
    error::Error,
    metadata::{
        tables::{
            ManifestResourceAttributes, ManifestResourceBuilder, ManifestResourceRaw, TableId,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    prelude::FlowType,
    CilObject, Result, ValidationConfig,
};

/// Information about an extracted embedded assembly.
#[derive(Debug, Clone)]
pub struct ExtractedAssembly {
    /// Raw bytes of the extracted assembly.
    pub data: Vec<u8>,
    /// Suggested filename for the assembly (if determinable).
    pub suggested_name: Option<String>,
    /// Whether this appears to be a valid PE/COFF file.
    pub is_valid_pe: bool,
}

impl ExtractedAssembly {
    /// Creates a new `ExtractedAssembly` from raw bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        let is_valid_pe = data.len() >= 2 && data[0] == b'M' && data[1] == b'Z';

        // Try to extract assembly name from the PE if valid
        let suggested_name = if is_valid_pe {
            Self::try_extract_name(&data)
        } else {
            None
        };

        Self {
            data,
            suggested_name,
            is_valid_pe,
        }
    }

    /// Attempts to extract the assembly name from PE metadata.
    fn try_extract_name(data: &[u8]) -> Option<String> {
        // Try to load as CilObject to get the assembly name
        let assembly =
            CilObject::from_mem_with_validation(data.to_vec(), ValidationConfig::disabled())
                .ok()?;

        assembly.assembly().map(|a| format!("{}.dll", a.name))
    }

    /// Returns the size of the assembly in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// A resource extracted from a hidden ConfuserEx assembly.
///
/// This represents a single ManifestResource entry that was hidden
/// in an encrypted assembly by ConfuserEx resource protection.
#[derive(Debug, Clone)]
pub struct ExtractedResource {
    /// Resource name (e.g., "MyApp.Resources.strings.resources").
    pub name: String,
    /// Resource visibility flags (as raw bits).
    pub flags: u32,
    /// Raw resource data bytes.
    pub data: Vec<u8>,
}

impl ExtractedResource {
    /// Returns the size of the resource data in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the resource is public.
    #[must_use]
    pub fn is_public(&self) -> bool {
        (self.flags & ManifestResourceAttributes::PUBLIC.bits()) != 0
    }
}

/// Result of resource decryption.
#[derive(Debug)]
pub struct ResourceDecryptionResult {
    /// Extracted embedded assemblies with metadata.
    pub assemblies: Vec<ExtractedAssembly>,
    /// Resources extracted from hidden assemblies.
    pub resources: Vec<ExtractedResource>,
    /// The method token that performed the decryption.
    pub decryptor_method: Option<Token>,
    /// Number of instructions executed during emulation.
    pub instructions_executed: u64,
    /// Tokens of methods/types that are ConfuserEx protection stubs.
    pub protection_stubs: Vec<Token>,
}

impl ResourceDecryptionResult {
    /// Returns true if any assemblies were extracted.
    #[must_use]
    pub fn has_assemblies(&self) -> bool {
        !self.assemblies.is_empty()
    }

    /// Returns true if any resources were extracted.
    #[must_use]
    pub fn has_resources(&self) -> bool {
        !self.resources.is_empty()
    }

    /// Returns the number of extracted assemblies.
    #[must_use]
    pub fn assembly_count(&self) -> usize {
        self.assemblies.len()
    }

    /// Returns the number of extracted resources.
    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Returns the total size of all extracted assemblies.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.assemblies.iter().map(ExtractedAssembly::size).sum()
    }

    /// Returns the total size of all extracted resources.
    #[must_use]
    pub fn total_resource_size(&self) -> usize {
        self.resources.iter().map(ExtractedResource::size).sum()
    }
}

/// Detects resource protection patterns and populates findings.
///
/// This is called by the orchestrator in detection.rs to detect
/// ConfuserEx resource protection.
///
/// Resource protection is detected by looking for:
/// - AppDomain.CurrentDomain.add_AssemblyResolve handler registration
/// - AppDomain.CurrentDomain.add_ResourceResolve handler registration
/// - Assembly.Load calls (for loading hidden assemblies)
/// - Delegate creation for event handlers
/// - Decompression calls (LZMA, Inflate, etc.)
pub fn detect(assembly: &CilObject, score: &DetectionScore, findings: &mut ConfuserExFindings) {
    for method_entry in assembly.methods().iter() {
        let method = method_entry.value();

        let mut has_assembly_resolve = false;
        let mut has_resource_resolve = false;
        let mut has_assembly_load = false;
        let mut has_decompress = false;
        let mut has_current_domain = false;

        for instr in method.instructions() {
            if instr.flow_type != FlowType::Call {
                continue;
            }

            let Operand::Token(token) = instr.operand else {
                continue;
            };

            let Some(type_name) = get_call_target_name(assembly, token) else {
                continue;
            };

            // AppDomain.CurrentDomain access
            if type_name.contains("AppDomain") && type_name.contains("CurrentDomain") {
                has_current_domain = true;
            }

            // AssemblyResolve event handler registration
            if type_name.contains("add_AssemblyResolve") || type_name.contains("AssemblyResolve") {
                has_assembly_resolve = true;
            }

            // ResourceResolve event handler registration
            if type_name.contains("add_ResourceResolve") || type_name.contains("ResourceResolve") {
                has_resource_resolve = true;
            }

            // Assembly.Load calls
            if type_name.contains("Assembly") && type_name.contains("Load") {
                has_assembly_load = true;
            }

            // Decompression calls
            if type_name.contains("Decompress")
                || type_name.contains("Lzma")
                || type_name.contains("Inflate")
                || type_name.contains("GZipStream")
                || type_name.contains("DeflateStream")
            {
                has_decompress = true;
            }
        }

        // Resource handler pattern: registers event handler + has assembly load
        let is_resource_handler = (has_assembly_resolve || has_resource_resolve)
            && has_current_domain
            && (has_assembly_load || has_decompress);

        if is_resource_handler {
            findings.resource_handler_methods.push(method.token);
            let locations = boxcar::Vec::new();
            locations.push(method.token);
            score.add(DetectionEvidence::BytecodePattern {
                name: format!(
                    "Resource handler (resolve={} load={} decompress={})",
                    has_assembly_resolve || has_resource_resolve,
                    has_assembly_load,
                    has_decompress
                ),
                locations,
                confidence: 5,
            });
        }
    }
}

/// Gets the fully qualified name of a call target from a token.
fn get_call_target_name(assembly: &CilObject, token: Token) -> Option<String> {
    let table_id = token.table();

    match table_id {
        // MethodDef
        0x06 => {
            let method = assembly.methods().get(&token)?;
            let method = method.value();
            Some(method.name.clone())
        }
        // MemberRef
        0x0A => {
            if let Some(member_ref) = assembly.refs_members().get(&token) {
                let member_ref = member_ref.value();
                let type_name = get_declaring_type_name(&member_ref.declaredby);
                return Some(format!("{}::{}", type_name, member_ref.name));
            }
            None
        }
        // MethodSpec - generic method instantiation, check the underlying method
        0x2B => {
            // MethodSpec wraps a MethodDef or MemberRef with generic args
            // For detection purposes, we can skip these as the underlying method
            // will be checked separately
            None
        }
        _ => None,
    }
}

/// Gets the type name from a CilTypeReference.
fn get_declaring_type_name(type_ref: &CilTypeReference) -> String {
    match type_ref {
        CilTypeReference::TypeRef(tr) => {
            let ns = tr.namespace().unwrap_or_default();
            let name = tr.name().unwrap_or_else(|| "Unknown".to_string());
            if ns.is_empty() {
                name
            } else {
                format!("{}.{}", ns, name)
            }
        }
        CilTypeReference::TypeDef(td) => {
            let ns = td.namespace().unwrap_or_default();
            let name = td.name().unwrap_or_else(|| "Unknown".to_string());
            if ns.is_empty() {
                name
            } else {
                format!("{}.{}", ns, name)
            }
        }
        CilTypeReference::TypeSpec(ts) => ts.name().unwrap_or_else(|| "TypeSpec".to_string()),
        _ => "Unknown".to_string(),
    }
}

/// Extracts ManifestResource entries from a hidden assembly.
///
/// This function loads the raw assembly bytes and extracts all embedded resources.
/// If the hidden assembly is a netmodule (no Assembly table), it falls back to
/// returning an empty list since netmodules typically don't contain the actual
/// resource data - they just define the manifest entries.
///
/// # Arguments
///
/// * `data` - Raw bytes of the hidden assembly or netmodule.
///
/// # Returns
///
/// A vector of extracted resources, or an empty vector if resources can't be extracted.
fn extract_resources_from_assembly(data: &[u8]) -> Result<Vec<ExtractedResource>> {
    // Try loading as a full CilObject (for assemblies with Assembly table)
    match CilObject::from_mem_with_validation(data.to_vec(), ValidationConfig::disabled()) {
        Ok(hidden_assembly) => {
            // Standard path: use the Resources container
            let resources = hidden_assembly.resources();
            let mut extracted = Vec::new();

            for entry in resources.iter() {
                let manifest = entry.value();

                // Only extract embedded resources (source == None means embedded)
                if manifest.source.is_some() {
                    continue;
                }

                // Get actual resource data
                if let Some(resource_data) = resources.get_data(manifest) {
                    extracted.push(ExtractedResource {
                        name: manifest.name.clone(),
                        flags: manifest.flags.bits(),
                        data: resource_data.to_vec(),
                    });
                }
            }

            Ok(extracted)
        }
        Err(_) => {
            // Failed to load as CilObject (likely a netmodule without Assembly table)
            // For now, return empty - netmodules need special handling
            // TODO: Implement direct parsing of ManifestResource table for netmodules
            Ok(Vec::new())
        }
    }
}

/// Attempts to decrypt resource-protected embedded assemblies.
///
/// This function uses emulation to run the resource initializer and capture
/// any Assembly.Load calls, extracting the decrypted assembly bytes.
///
/// # Arguments
///
/// * `assembly` - The resource-protected assembly.
/// * `events` - Event log for recording activity.
///
/// # Returns
///
/// A new `CilObject` with resource protection removed, along with any extracted
/// embedded assemblies in the `ResourceDecryptionResult`.
///
/// # Extracted Assemblies
///
/// The extracted assemblies are complete .NET assemblies that were hidden by ConfuserEx.
/// They should be saved as separate files alongside the deobfuscated main assembly.
/// The `ExtractedAssembly::suggested_name` field provides a filename suggestion based
/// on the assembly's metadata.
///
/// # Errors
///
/// Returns an error if emulation fails catastrophically.
pub fn decrypt_resources(
    assembly: CilObject,
    events: &mut EventLog,
) -> Result<(CilObject, ResourceDecryptionResult)> {
    // Keep original bytes for rebuilding
    let pe_bytes = assembly.file().data().to_vec();

    // Wrap in Arc for emulation (emulation API requires Arc)
    let assembly_arc = Arc::new(assembly);

    // Find resource protection candidates
    let candidates = find_candidates(&assembly_arc, ProtectionType::Resources);
    let result = if candidates.is_empty() {
        ResourceDecryptionResult {
            assemblies: Vec::new(),
            resources: Vec::new(),
            decryptor_method: None,
            instructions_executed: 0,
            protection_stubs: Vec::new(),
        }
    } else {
        // Try each candidate until we successfully extract assemblies
        let mut final_result = None;
        for candidate in candidates.iter() {
            match try_emulate_resource_decryptor(Arc::clone(&assembly_arc), candidate.token, events)
            {
                Ok(result) if result.has_assemblies() || result.has_resources() => {
                    // Log extraction details
                    events.info(format!(
                        "Extracted {} hidden assemblies ({} bytes) and {} resources ({} bytes) via method 0x{:08x}",
                        result.assembly_count(),
                        result.total_size(),
                        result.resource_count(),
                        result.total_resource_size(),
                        candidate.token.value()
                    ));

                    // Log individual assembly names
                    for (i, asm) in result.assemblies.iter().enumerate() {
                        let name = asm.suggested_name.as_deref().unwrap_or("<unknown>");
                        events.info(format!(
                            "  Hidden assembly {}: {} ({} bytes, valid PE: {})",
                            i + 1,
                            name,
                            asm.size(),
                            asm.is_valid_pe
                        ));
                    }

                    // Log individual resource names
                    for (i, res) in result.resources.iter().enumerate() {
                        let visibility = if res.is_public() { "public" } else { "private" };
                        events.info(format!(
                            "  Resource {}: {} ({} bytes, {})",
                            i + 1,
                            res.name,
                            res.size(),
                            visibility
                        ));
                    }

                    final_result = Some(result);
                    break;
                }
                Ok(_) => continue,
                Err(e) => {
                    events.warn(format!(
                        "Resource emulation failed for 0x{:08x}: {}",
                        candidate.token.value(),
                        e
                    ));
                    continue;
                }
            }
        }
        final_result.unwrap_or(ResourceDecryptionResult {
            assemblies: Vec::new(),
            resources: Vec::new(),
            decryptor_method: None,
            instructions_executed: 0,
            protection_stubs: Vec::new(),
        })
    };

    // Drop the Arc - we'll return a new CilObject
    drop(assembly_arc);

    // Early exit: no resources to insert, just reload unchanged
    if !result.has_resources() {
        let new_assembly =
            CilObject::from_mem_with_validation(pe_bytes, ValidationConfig::analysis())?;
        return Ok((new_assembly, result));
    }

    // Create CilAssembly for modifications
    let mut cil_assembly =
        CilAssembly::from_bytes_with_validation(pe_bytes.clone(), ValidationConfig::analysis())?;

    // Remove existing ManifestResource rows with matching names to avoid duplicates.
    // We replace ANY existing resource with the same name (embedded or external)
    // to ensure clean replacement with the decrypted version.
    let names_to_insert: std::collections::HashSet<_> =
        result.resources.iter().map(|r| r.name.as_str()).collect();

    let rids_to_remove = find_manifest_resources_by_name(&cil_assembly, &names_to_insert);
    for rid in rids_to_remove {
        if let Err(e) = cil_assembly.table_row_remove(TableId::ManifestResource, rid) {
            events.warn(format!(
                "Failed to remove existing ManifestResource row {}: {}",
                rid, e
            ));
        }
    }

    // Insert each extracted resource
    for resource in &result.resources {
        let builder = ManifestResourceBuilder::new()
            .name(&resource.name)
            .flags(resource.flags)
            .resource_data(&resource.data);

        match builder.build(&mut cil_assembly) {
            Ok(_) => events.info(format!(
                "Inserted resource: {} ({} bytes)",
                resource.name,
                resource.size()
            )),
            Err(e) => events.warn(format!(
                "Failed to insert resource '{}': {}",
                resource.name, e
            )),
        }
    }

    // Build and return the modified assembly
    let new_assembly = cil_assembly
        .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())?;
    Ok((new_assembly, result))
}

/// Finds ManifestResource row IDs that match any of the given names.
fn find_manifest_resources_by_name(
    cil_assembly: &CilAssembly,
    names: &std::collections::HashSet<&str>,
) -> Vec<u32> {
    let view = cil_assembly.view();
    let Some(strings) = view.strings() else {
        return Vec::new();
    };
    let Some(tables) = view.tables() else {
        return Vec::new();
    };
    let Some(manifest_table) = tables.table::<ManifestResourceRaw>() else {
        return Vec::new();
    };

    manifest_table
        .iter()
        .filter_map(|row| {
            strings
                .get(row.name as usize)
                .ok()
                .filter(|name| names.contains(*name))
                .map(|_| row.rid)
        })
        .collect()
}

/// Attempts to emulate a single resource decryptor candidate.
fn try_emulate_resource_decryptor(
    assembly: Arc<CilObject>,
    method_token: Token,
    _events: &mut EventLog,
) -> Result<ResourceDecryptionResult> {
    // BCL stream hooks track state via HeapObject::Stream, so no custom
    // registration needed - the default BCL hooks handle MemoryStream operations.
    // We add the LZMA hook to handle ConfuserEx's inline LZMA decompressor natively.
    let process = ProcessBuilder::new()
        .assembly_arc(Arc::clone(&assembly))
        .with_max_instructions(2_000_000)
        .with_max_call_depth(100)
        .capture_assemblies() // Enable assembly capture for embedded assembly extraction
        .hook(create_lzma_hook()) // Native LZMA decompression for ConfuserEx
        .build()?;

    let outcome = process.execute_method(method_token, vec![])?;
    let instructions_executed = match outcome {
        EmulationOutcome::Completed { instructions, .. }
        | EmulationOutcome::Breakpoint { instructions, .. } => instructions,
        EmulationOutcome::LimitReached { limit, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Resource emulation exceeded limit: {:?}",
                limit
            )));
        }
        EmulationOutcome::Stopped { reason, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Resource emulation stopped: {}",
                reason
            )));
        }
        EmulationOutcome::UnhandledException { exception, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Resource emulation threw exception: {:?}",
                exception
            )));
        }
        EmulationOutcome::RequiresSymbolic { reason, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Resource emulation requires symbolic execution: {}",
                reason
            )));
        }
    };

    // Convert captured assembly bytes to ExtractedAssembly with metadata
    let assemblies: Vec<ExtractedAssembly> = process
        .capture()
        .assemblies()
        .iter()
        .map(|a| ExtractedAssembly::new(a.data.clone()))
        .collect();

    // Extract resources from each hidden assembly
    let mut resources = Vec::new();
    for asm in &assemblies {
        if asm.is_valid_pe {
            if let Ok(extracted) = extract_resources_from_assembly(&asm.data) {
                resources.extend(extracted);
            }
        }
    }

    // The decryptor method itself is a protection stub that should be removed
    let protection_stubs = vec![method_token];

    Ok(ResourceDecryptionResult {
        assemblies,
        resources,
        decryptor_method: Some(method_token),
        instructions_executed,
        protection_stubs,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::{
            changes::EventLog,
            obfuscators::confuserex::{
                candidates::{find_candidates, ProtectionType},
                resources::decrypt_resources,
            },
        },
        CilObject, ValidationConfig,
    };

    const MAXIMUM_PATH: &str = "tests/samples/packers/confuserex/mkaring_maximum.exe";
    const RESOURCES_PATH: &str = "tests/samples/packers/confuserex/mkaring_resources.exe";

    #[test]
    fn test_find_resource_candidates() {
        let assembly =
            CilObject::from_path_with_validation(MAXIMUM_PATH, ValidationConfig::analysis())
                .expect("Failed to load assembly");

        let candidates = find_candidates(&assembly, ProtectionType::Resources);

        println!("Resource candidates found: {}", candidates.candidates.len());
        for (i, c) in candidates.iter().enumerate() {
            println!(
                "  {}. 0x{:08x} score={} reasons={:?}",
                i + 1,
                c.token.value(),
                c.score,
                c.reasons
            );
        }
    }

    #[test]
    fn test_find_resource_candidates_in_resources_sample() {
        let assembly =
            CilObject::from_path_with_validation(RESOURCES_PATH, ValidationConfig::analysis())
                .expect("Failed to load assembly");

        let candidates = find_candidates(&assembly, ProtectionType::Resources);

        println!(
            "Resource candidates in resources sample: {}",
            candidates.candidates.len()
        );
        for (i, c) in candidates.iter().enumerate() {
            println!(
                "  {}. 0x{:08x} score={} reasons={:?}",
                i + 1,
                c.token.value(),
                c.score,
                c.reasons
            );
        }

        // Resources sample should have candidates with resource-specific patterns
        assert!(
            !candidates.is_empty(),
            "Resources sample should have resource protection candidates"
        );
    }

    #[test]
    fn test_decrypt_resources() {
        let assembly =
            CilObject::from_path_with_validation(RESOURCES_PATH, ValidationConfig::analysis())
                .expect("Failed to load assembly");

        // First show candidates
        let candidates = find_candidates(&assembly, ProtectionType::Resources);
        println!("Resource candidates: {}", candidates.candidates.len());
        for (i, c) in candidates.iter().enumerate() {
            println!(
                "  {}. 0x{:08x} score={} reasons={:?}",
                i + 1,
                c.token.value(),
                c.score,
                c.reasons
            );
        }

        let mut events = EventLog::new();
        let result = decrypt_resources(assembly, &mut events);

        // Show events
        println!("Events logged: {}", events.len());
        for event in events.iter() {
            println!("  Event: {:?}", event);
        }

        match result {
            Ok((deobfuscated_assembly, decryption_result)) => {
                println!(
                    "Resource decryption result: {} assemblies extracted",
                    decryption_result.assembly_count()
                );
                if let Some(method) = decryption_result.decryptor_method {
                    println!("Decryptor method: 0x{:08x}", method.value());
                }
                println!(
                    "Instructions executed: {}",
                    decryption_result.instructions_executed
                );

                for (i, asm) in decryption_result.assemblies.iter().enumerate() {
                    println!("  Assembly {}: {} bytes", i + 1, asm.size());
                }

                // Also print extracted resources
                for (i, res) in decryption_result.resources.iter().enumerate() {
                    println!("  Resource {}: {} ({} bytes)", i + 1, res.name, res.size());
                }

                // Verify resources were extracted from the assemblies
                assert!(
                    decryption_result.has_resources(),
                    "Should have extracted at least one resource"
                );
                assert_eq!(
                    decryption_result.resource_count(),
                    1,
                    "Should have extracted exactly one resource (duplicates are filtered)"
                );
                assert_eq!(
                    decryption_result.resources[0].name, "ResourceTestApp.testimage.bmp",
                    "Resource name should match expected"
                );

                // Verify resources are present in the final CilObject
                println!("\nVerifying resources in deobfuscated assembly:");
                let final_resources = deobfuscated_assembly.resources();
                println!(
                    "  Resource count in final assembly: {}",
                    final_resources.len()
                );

                // Find our inserted resource and verify it's accessible
                let mut found_resource = false;
                for entry in final_resources.iter() {
                    let manifest = entry.value();
                    println!(
                        "    - {} ({} bytes, embedded: {})",
                        manifest.name,
                        manifest.data_size,
                        manifest.source.is_none()
                    );
                    if manifest.name == "ResourceTestApp.testimage.bmp" {
                        found_resource = true;

                        // Verify resource data is accessible
                        let data = final_resources
                            .get_data(manifest)
                            .expect("Resource data should be accessible");

                        // The original testimage.bmp is 246 bytes
                        assert_eq!(
                            data.len(),
                            246,
                            "Resource data size should match original (246 bytes)"
                        );
                    }
                }
                assert!(
                    found_resource,
                    "Inserted resource should be present in final assembly"
                );
            }
            Err(e) => {
                panic!("Resource decryption failed: {}", e);
            }
        }
    }
}
