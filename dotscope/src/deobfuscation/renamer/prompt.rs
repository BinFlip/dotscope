//! FIM prompt construction for LLM-powered renaming.
//!
//! Builds Fill-in-the-Middle (FIM) prompts from [`RenameContext`] data.
//! The prompts use special tokens (`<|fim_prefix|>`, `<|fim_suffix|>`,
//! `<|fim_middle|>`) compatible with Codestral/Codellama-style models.
//!
//! Each [`IdentifierKind`] has a distinct template optimized for the
//! information most useful for that kind of rename.

use crate::deobfuscation::renamer::context::{IdentifierKind, PhaseInfo, RenameContext};

/// Builds a FIM prompt from a rename context.
///
/// Returns a `(prefix, suffix)` tuple. The model is expected to generate
/// the identifier name between `<|fim_middle|>` and the next stop token.
///
/// # Arguments
///
/// * `context` - The extracted features for the identifier.
/// * `max_phases` - Maximum number of phases to include before truncation.
///
/// # Returns
///
/// `(prefix_string, suffix_string)` for FIM inference.
pub fn build_fim_prompt(context: &RenameContext, max_phases: usize) -> (String, String) {
    let kind = context.kind.unwrap_or(IdentifierKind::Method);

    match kind {
        IdentifierKind::Method => build_method_prompt(context, max_phases),
        IdentifierKind::Field => build_field_prompt(context),
        IdentifierKind::Type => build_type_prompt(context),
        IdentifierKind::Parameter => build_parameter_prompt(context),
    }
}

/// Builds a FIM prompt for labeling a single phase.
///
/// Used during Phase 2 of the cascade to generate short descriptive labels
/// for each method phase (e.g., "Load encrypted resource from assembly").
///
/// # Arguments
///
/// * `phase` - The phase info to label.
///
/// # Returns
///
/// `(prefix_string, suffix_string)` for FIM inference.
pub fn build_phase_label_prompt(phase: &PhaseInfo) -> (String, String) {
    let mut prefix = String::from("<|fim_prefix|>// ");

    let suffix = if phase.call_targets.is_empty() {
        // Transform region: describe by opcode profile
        let mut ops_parts = Vec::new();
        if let Some(ref profile) = phase.opcode_profile {
            if profile.bitwise > 0 {
                ops_parts.push(format!("bitwise: {}", profile.bitwise));
            }
            if profile.arithmetic > 0 {
                ops_parts.push(format!("arithmetic: {}", profile.arithmetic));
            }
            if profile.array > 0 {
                ops_parts.push(format!("array: {}", profile.array));
            }
            if profile.comparison > 0 {
                ops_parts.push(format!("comparison: {}", profile.comparison));
            }
        }
        let structure_note = phase
            .structure
            .as_deref()
            .map(|s| format!("\n// Structure: {s}"))
            .unwrap_or_default();

        format!(
            "\n// Ops: [{}]{structure_note}<|fim_middle|>",
            ops_parts.join(", ")
        )
    } else {
        // Call-based phase
        let calls = phase.call_targets.join(", ");
        format!("\n// Calls: {calls}<|fim_middle|>")
    };

    prefix.push_str("<|fim_suffix|>");
    (prefix, suffix)
}

/// Builds a method naming prompt (small or large).
///
/// Small methods (with a call-site skeleton) use the skeleton as suffix context.
/// Large methods use a phase narrative as prefix context.
///
/// # Arguments
///
/// * `context` - The rename context with method features.
/// * `max_phases` - Maximum phases to include before truncation.
///
/// # Returns
///
/// `(prefix, suffix)` tuple for FIM inference.
fn build_method_prompt(context: &RenameContext, max_phases: usize) -> (String, String) {
    let mut prefix = String::new();
    prefix.push_str("<|fim_prefix|>");

    // Shared context: render call targets, strings, field accesses, siblings.
    // These are the strongest naming signals — external API names, constants,
    // and already-renamed siblings provide semantic cues the LLM needs.
    render_shared_context(&mut prefix, context);

    if let Some(ref skeleton) = context.call_site_skeleton {
        // Small method: use skeleton as suffix
        let return_type = context.dotnet_type.as_deref().unwrap_or("void");
        let params = format_params(&context.parameters);

        prefix.push_str(&format!("// Returns: {return_type}\n"));
        prefix.push_str(&format!("public {return_type} "));

        let suffix = format!("({params}) {{\n{skeleton}\n}}<|fim_middle|>");
        (prefix, suffix)
    } else {
        // Large method: use phase narrative
        let phases = truncate_phases(&context.phase_narrative, max_phases);
        for (i, phase) in phases.iter().enumerate() {
            prefix.push_str(&format!(
                "// Phase {}: {}\n",
                i.saturating_add(1),
                phase.label
            ));
            if !phase.call_targets.is_empty() {
                let calls = phase.call_targets.join(", ");
                prefix.push_str(&format!("//   [calls: {calls}]\n"));
            }
            if let Some(ref profile) = phase.opcode_profile {
                if profile.bitwise > 0 || profile.arithmetic > 0 {
                    let mut parts = Vec::new();
                    if profile.bitwise > 0 {
                        parts.push(format!("bitwise {}", profile.bitwise));
                    }
                    if profile.arithmetic > 0 {
                        parts.push(format!("arithmetic {}", profile.arithmetic));
                    }
                    if profile.array > 0 {
                        parts.push(format!("array {}", profile.array));
                    }
                    prefix.push_str(&format!("//   [ops: {}]\n", parts.join(", ")));
                }
            }
        }

        let return_type = context.dotnet_type.as_deref().unwrap_or("void");
        let params = format_params(&context.parameters);

        prefix.push_str(&format!("// Returns: {return_type}\n"));
        prefix.push_str(&format!("public {return_type} "));

        let suffix = format!("({params}) {{\n}}<|fim_middle|>");
        (prefix, suffix)
    }
}

/// Renders shared context lines (call targets, strings, fields, siblings)
/// into the prefix. These lines appear before the signature in all method
/// prompt variants.
fn render_shared_context(prefix: &mut String, context: &RenameContext) {
    if !context.interfaces.is_empty() {
        let interfaces = format_interfaces(&context.interfaces);
        prefix.push_str(&format!("// Implements: {interfaces}\n"));
    }

    if !context.siblings.is_empty() {
        let siblings = context.siblings.join(", ");
        prefix.push_str(&format!("// Sibling members: {siblings}\n"));
    }

    if !context.call_targets.is_empty() {
        let calls = context.call_targets.join(", ");
        prefix.push_str(&format!("// API calls: {calls}\n"));
    }

    if !context.string_literals.is_empty() {
        // Limit to first 5 strings to avoid prompt bloat
        let display: Vec<String> = context
            .string_literals
            .iter()
            .take(5)
            .map(|s| {
                if s.len() > 30 {
                    format!("\"{}...\"", &s[..27])
                } else {
                    format!("\"{s}\"")
                }
            })
            .collect();
        prefix.push_str(&format!("// Strings: {}\n", display.join(", ")));
    }

    if !context.field_accesses.is_empty() {
        let fields = context.field_accesses.join(", ");
        prefix.push_str(&format!("// Fields: {fields}\n"));
    }

    render_rejected_names(prefix, context);
    render_caller_context(prefix, context);
}

/// Renders the rejected names constraint into the prefix.
///
/// When retrying after a duplicate, this tells the LLM which names
/// are already taken so it can suggest something different.
fn render_rejected_names(prefix: &mut String, context: &RenameContext) {
    if !context.rejected_names.is_empty() {
        let rejected = context.rejected_names.join(", ");
        prefix.push_str(&format!(
            "// Do NOT use these names (already taken): {rejected}\n"
        ));
    }
}

/// Renders caller-side context into the prefix.
///
/// Shows which methods call this one, what nearby strings they have,
/// and what the return value feeds into — critical for context-starved
/// methods that have no external calls or strings of their own.
fn render_caller_context(prefix: &mut String, context: &RenameContext) {
    if context.caller_context.is_empty() {
        return;
    }

    prefix.push_str("// Called by:\n");
    for caller in context.caller_context.iter().take(3) {
        prefix.push_str(&format!("//   {}", caller.caller_name));

        let mut parts = Vec::new();
        if !caller.nearby_strings.is_empty() {
            let strs: Vec<String> = caller
                .nearby_strings
                .iter()
                .take(3)
                .map(|s| {
                    if s.len() > 40 {
                        format!("\"{}...\"", &s[..37])
                    } else {
                        format!("\"{s}\"")
                    }
                })
                .collect();
            parts.push(format!("strings: {}", strs.join(", ")));
        }
        if let Some(ref usage) = caller.return_usage {
            parts.push(format!("result used in {usage}"));
        }

        if parts.is_empty() {
            prefix.push('\n');
        } else {
            prefix.push_str(&format!(" — {}\n", parts.join("; ")));
        }
    }
}

/// Builds a field naming prompt.
///
/// Includes usage context from sibling members, field type, and API call anchors.
///
/// # Arguments
///
/// * `context` - The rename context with field features.
///
/// # Returns
///
/// `(prefix, suffix)` tuple for FIM inference.
fn build_field_prompt(context: &RenameContext) -> (String, String) {
    let mut prefix = String::from("<|fim_prefix|>");

    // Usage context from siblings
    if !context.siblings.is_empty() {
        let used_in = context.siblings.join(", ");
        prefix.push_str(&format!("// Used in: {used_in}\n"));
    }

    // Type info
    if let Some(ref dotnet_type) = context.dotnet_type {
        prefix.push_str(&format!("// Type: {dotnet_type}\n"));
    }

    // API call anchors
    for anchor in &context.api_calls {
        if let Some(pos) = anchor.argument_position {
            prefix.push_str(&format!(
                "// Passed to {} as arg {pos}\n",
                anchor.method_name
            ));
        }
    }

    render_rejected_names(&mut prefix, context);

    let field_type = context.dotnet_type.as_deref().unwrap_or("object");
    prefix.push_str(&format!("private {field_type} "));

    let suffix = ";<|fim_middle|>".to_string();
    (prefix, suffix)
}

/// Builds a type naming prompt.
///
/// Includes member list, interfaces, and base class information.
///
/// # Arguments
///
/// * `context` - The rename context with type features.
///
/// # Returns
///
/// `(prefix, suffix)` tuple for FIM inference.
fn build_type_prompt(context: &RenameContext) -> (String, String) {
    let mut prefix = String::from("<|fim_prefix|>");

    // Members list
    if !context.siblings.is_empty() {
        let members = context.siblings.join(", ");
        prefix.push_str(&format!("// Members: {members}\n"));
    }

    // Interfaces and base class
    if !context.interfaces.is_empty() {
        let interfaces = context.interfaces.join(", ");
        prefix.push_str(&format!("// Implements: {interfaces}\n"));
    }
    if let Some(ref base) = context.base_class {
        prefix.push_str(&format!("// Base: {base}\n"));
    }

    render_rejected_names(&mut prefix, context);

    prefix.push_str("public class ");

    let mut suffix = String::new();
    // Add inheritance clause
    let mut inherits = Vec::new();
    if let Some(ref base) = context.base_class {
        if base != "System.Object" {
            inherits.push(base.clone());
        }
    }
    inherits.extend(context.interfaces.iter().cloned());

    if !inherits.is_empty() {
        suffix.push_str(&format!(" : {}", inherits.join(", ")));
    }

    suffix.push_str(" {\n}");
    suffix.push_str("<|fim_middle|>");
    (prefix, suffix)
}

/// Builds a parameter naming prompt.
///
/// Includes API call anchors and parent method context.
///
/// # Arguments
///
/// * `context` - The rename context with parameter features.
///
/// # Returns
///
/// `(prefix, suffix)` tuple for FIM inference.
fn build_parameter_prompt(context: &RenameContext) -> (String, String) {
    let mut prefix = String::from("<|fim_prefix|>");

    // Parent method context
    if let Some(ref parent) = context.parent_type {
        prefix.push_str(&format!("// In method: {parent}\n"));
    }

    // API call anchors for this parameter
    for anchor in &context.api_calls {
        if let Some(pos) = anchor.argument_position {
            prefix.push_str(&format!(
                "// Passed to {} as arg {pos}\n",
                anchor.method_name
            ));
        }
    }

    // Call targets from the owning method provide naming context
    if !context.call_targets.is_empty() {
        let calls = context.call_targets.join(", ");
        prefix.push_str(&format!("// Method calls: {calls}\n"));
    }

    // Sibling parameter names already committed
    if !context.siblings.is_empty() {
        let siblings = context.siblings.join(", ");
        prefix.push_str(&format!("// Other params: {siblings}\n"));
    }

    render_rejected_names(&mut prefix, context);

    let param_type = context.dotnet_type.as_deref().unwrap_or("object");
    prefix.push_str(&format!("({param_type} "));

    let suffix = ")<|fim_middle|>".to_string();
    (prefix, suffix)
}

/// Formats a parameter list for method signature display.
///
/// Produces comma-separated `"type name"` pairs. Parameters without
/// a known name use `param_N` placeholders.
///
/// # Arguments
///
/// * `params` - The parameter list to format.
///
/// # Returns
///
/// A comma-separated parameter string (e.g., `"string path, int param_1"`).
fn format_params(params: &[crate::deobfuscation::renamer::context::ParamInfo]) -> String {
    if params.is_empty() {
        return String::new();
    }

    params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let fallback = format!("param_{i}");
            let name = p.known_name.as_deref().unwrap_or(&fallback);
            format!("{} {name}", p.dotnet_type)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Formats an interface list as a comma-separated string.
///
/// # Arguments
///
/// * `interfaces` - The interface names to format.
///
/// # Returns
///
/// A comma-separated string (e.g., `"IDisposable, IEnumerable"`).
fn format_interfaces(interfaces: &[String]) -> String {
    interfaces.join(", ")
}

/// Truncates phase list if it exceeds the budget.
///
/// If there are more than `max_phases` phases, keeps the first half
/// and last half, producing a condensed representation.
///
/// # Arguments
///
/// * `phases` - The full list of phases.
/// * `max_phases` - Maximum number of phases to retain.
///
/// # Returns
///
/// A vector of references to the retained phases.
fn truncate_phases(phases: &[PhaseInfo], max_phases: usize) -> Vec<&PhaseInfo> {
    if phases.len() <= max_phases {
        return phases.iter().collect();
    }

    let half = max_phases / 2;
    let mut result: Vec<&PhaseInfo> = Vec::new();
    if let Some(front) = phases.get(..half) {
        result.extend(front);
    }
    let tail_start = phases.len().saturating_sub(half);
    if let Some(back) = phases.get(tail_start..) {
        result.extend(back);
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::renamer::{
        context::{IdentifierKind, ParamInfo, PhaseInfo, RenameContext},
        prompt::{build_fim_prompt, build_phase_label_prompt},
    };

    /// Default max phases used in tests.
    const TEST_MAX_PHASES: usize = 6;

    #[test]
    fn test_prompt_method_small() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            dotnet_type: Some("void".to_string()),
            call_site_skeleton: Some("    File.WriteAllText(var_0, var_1);".to_string()),
            parameters: vec![
                ParamInfo {
                    dotnet_type: "string".to_string(),
                    known_name: Some("path".to_string()),
                },
                ParamInfo {
                    dotnet_type: "string".to_string(),
                    known_name: None,
                },
            ],
            ..Default::default()
        };

        let (prefix, suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(prefix.contains("<|fim_prefix|>"));
        assert!(prefix.contains("Returns: void"));
        assert!(suffix.contains("File.WriteAllText"));
        assert!(suffix.contains("<|fim_middle|>"));
    }

    #[test]
    fn test_prompt_method_large() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            dotnet_type: Some("void".to_string()),
            phase_narrative: vec![
                PhaseInfo {
                    label: "Load resource".to_string(),
                    call_targets: vec!["Assembly.GetManifestResourceStream".to_string()],
                    opcode_profile: None,
                    structure: None,
                },
                PhaseInfo {
                    label: "Decrypt data".to_string(),
                    call_targets: vec![],
                    opcode_profile: None,
                    structure: Some("loop".to_string()),
                },
            ],
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(prefix.contains("Phase 1: Load resource"));
        assert!(prefix.contains("Phase 2: Decrypt data"));
    }

    /// Method prompts must render call_targets from the context.
    #[test]
    fn test_prompt_method_renders_call_targets() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            dotnet_type: Some("byte[]".to_string()),
            call_targets: vec![
                "System.IO.File::ReadAllText".to_string(),
                "System.Text.Encoding::GetBytes".to_string(),
            ],
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(
            prefix.contains("API calls: System.IO.File::ReadAllText"),
            "Prompt should contain call targets, got:\n{prefix}"
        );
        assert!(
            prefix.contains("System.Text.Encoding::GetBytes"),
            "Prompt should contain all call targets"
        );
    }

    /// Method prompts must render string_literals from the context.
    #[test]
    fn test_prompt_method_renders_string_literals() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            dotnet_type: Some("void".to_string()),
            string_literals: vec!["Hello World".to_string(), "config.json".to_string()],
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(
            prefix.contains("Strings: \"Hello World\", \"config.json\""),
            "Prompt should contain string literals, got:\n{prefix}"
        );
    }

    /// Method prompts must render field_accesses from the context.
    #[test]
    fn test_prompt_method_renders_field_accesses() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            dotnet_type: Some("void".to_string()),
            field_accesses: vec!["Config.filePath".to_string(), "Config.timeout".to_string()],
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(
            prefix.contains("Fields: Config.filePath, Config.timeout"),
            "Prompt should contain field accesses, got:\n{prefix}"
        );
    }

    /// Method prompts must render sibling methods from the context.
    #[test]
    fn test_prompt_method_renders_siblings() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            dotnet_type: Some("void".to_string()),
            siblings: vec!["Initialize".to_string(), "Shutdown".to_string()],
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(
            prefix.contains("Sibling members: Initialize, Shutdown"),
            "Prompt should contain siblings, got:\n{prefix}"
        );
    }

    /// Small method prompt should include BOTH skeleton and shared context.
    #[test]
    fn test_prompt_method_small_with_full_context() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            dotnet_type: Some("void".to_string()),
            call_site_skeleton: Some("    File.WriteAllText(var_0, var_1);".to_string()),
            call_targets: vec!["System.IO.File::WriteAllText".to_string()],
            string_literals: vec!["/tmp/output.txt".to_string()],
            siblings: vec!["ReadConfig".to_string()],
            parameters: vec![ParamInfo {
                dotnet_type: "string".to_string(),
                known_name: Some("path".to_string()),
            }],
            ..Default::default()
        };

        let (prefix, suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        // Shared context in prefix
        assert!(prefix.contains("API calls:"), "Should have call targets");
        assert!(prefix.contains("Strings:"), "Should have string literals");
        assert!(prefix.contains("Sibling members:"), "Should have siblings");
        // Skeleton in suffix
        assert!(
            suffix.contains("File.WriteAllText"),
            "Skeleton should be in suffix"
        );
    }

    /// Empty context should produce a minimal prompt without crashing.
    #[test]
    fn test_prompt_method_empty_context() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            ..Default::default()
        };

        let (prefix, suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(
            prefix.contains("Returns: void"),
            "Should have default return type"
        );
        assert!(suffix.contains("<|fim_middle|>"), "Should have FIM token");
        // No context lines for empty vectors
        assert!(!prefix.contains("API calls:"), "No call targets = no line");
        assert!(!prefix.contains("Strings:"), "No strings = no line");
        assert!(!prefix.contains("Fields:"), "No fields = no line");
        assert!(!prefix.contains("Sibling"), "No siblings = no line");
    }

    #[test]
    fn test_prompt_field() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Field),
            dotnet_type: Some("System.String".to_string()),
            siblings: vec!["ProcessData".to_string(), "Initialize".to_string()],
            ..Default::default()
        };

        let (prefix, suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(prefix.contains("Used in: ProcessData, Initialize"));
        assert!(prefix.contains("Type: System.String"));
        assert!(suffix.contains("<|fim_middle|>"));
    }

    #[test]
    fn test_prompt_type() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Type),
            base_class: Some("System.Object".to_string()),
            interfaces: vec!["IDisposable".to_string()],
            siblings: vec!["ProcessData".to_string(), "Dispose".to_string()],
            ..Default::default()
        };

        let (prefix, suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(prefix.contains("Members: ProcessData, Dispose"));
        assert!(prefix.contains("Implements: IDisposable"));
        assert!(suffix.contains(": IDisposable"));
    }

    #[test]
    fn test_prompt_parameter() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Parameter),
            dotnet_type: Some("string".to_string()),
            parent_type: Some("WriteConfig".to_string()),
            ..Default::default()
        };

        let (prefix, suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(prefix.contains("In method: WriteConfig"));
        assert!(prefix.contains("(string "));
        assert!(suffix.contains("<|fim_middle|>"));
    }

    /// Parameter prompt should include call targets from the owning method.
    #[test]
    fn test_prompt_parameter_with_method_context() {
        use crate::deobfuscation::renamer::context::ApiCallInfo;

        let ctx = RenameContext {
            kind: Some(IdentifierKind::Parameter),
            dotnet_type: Some("byte[]".to_string()),
            parent_type: Some("DecryptData".to_string()),
            call_targets: vec!["System.Security.Cryptography.Aes::Create".to_string()],
            api_calls: vec![ApiCallInfo {
                method_name: "Aes::CreateDecryptor".to_string(),
                argument_position: Some(0),
            }],
            siblings: vec!["key".to_string()],
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(
            prefix.contains("In method: DecryptData"),
            "Should show parent method"
        );
        assert!(
            prefix.contains("Passed to Aes::CreateDecryptor as arg 0"),
            "Should show API anchor"
        );
        assert!(
            prefix.contains("Method calls: System.Security.Cryptography.Aes::Create"),
            "Should show owning method's call targets"
        );
        assert!(
            prefix.contains("Other params: key"),
            "Should show sibling params"
        );
    }

    #[test]
    fn test_phase_label_prompt_calls() {
        let phase = PhaseInfo {
            label: String::new(),
            call_targets: vec![
                "Assembly.GetManifestResourceStream".to_string(),
                "BinaryReader.ReadBytes".to_string(),
            ],
            opcode_profile: None,
            structure: None,
        };

        let (_prefix, suffix) = build_phase_label_prompt(&phase);
        assert!(suffix.contains("Assembly.GetManifestResourceStream"));
        assert!(suffix.contains("BinaryReader.ReadBytes"));
    }

    #[test]
    fn test_context_budget_truncation() {
        let phases: Vec<PhaseInfo> = (0..10)
            .map(|i| PhaseInfo {
                label: format!("Step_{i}"),
                call_targets: vec![],
                opcode_profile: None,
                structure: None,
            })
            .collect();

        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            phase_narrative: phases,
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        // Truncation keeps first 3 + last 3 = 6 phases
        // Prompt uses 1-based numbering: "Phase 1: Step_0", "Phase 2: Step_1", etc.
        assert!(prefix.contains("Step_0"), "First phase should be present");
        assert!(prefix.contains("Step_1"), "Second phase should be present");
        assert!(prefix.contains("Step_2"), "Third phase should be present");
        assert!(prefix.contains("Step_7"), "Third-to-last should be present");
        assert!(prefix.contains("Step_9"), "Last phase should be present");
        // Middle phases should be elided
        assert!(
            !prefix.contains("Step_4"),
            "Middle phase should be truncated"
        );
    }

    /// String literals longer than 30 chars should be truncated in the prompt.
    #[test]
    fn test_prompt_string_truncation() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            string_literals: vec![
                "This is a very long string that exceeds thirty characters".to_string()
            ],
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(
            prefix.contains("...\""),
            "Long strings should be truncated with '...', got:\n{prefix}"
        );
        assert!(
            !prefix.contains("thirty characters"),
            "Truncated portion should not appear"
        );
    }

    /// At most 5 string literals should appear in the prompt.
    #[test]
    fn test_prompt_string_limit() {
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            string_literals: (0..10).map(|i| format!("str_{i}")).collect(),
            ..Default::default()
        };

        let (prefix, _suffix) = build_fim_prompt(&ctx, TEST_MAX_PHASES);
        assert!(prefix.contains("str_0"), "First string should be present");
        assert!(prefix.contains("str_4"), "Fifth string should be present");
        assert!(!prefix.contains("str_5"), "Sixth string should be excluded");
    }
}
