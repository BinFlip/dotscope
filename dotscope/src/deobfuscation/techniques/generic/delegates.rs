//! Delegate proxy detection via SSA analysis.
//!
//! Detects delegate-based call indirection where every method call is hidden
//! behind a delegate proxy class. Each proxy class:
//!
//! 1. Inherits from `System.MulticastDelegate`
//! 2. Has a static singleton field of its own type
//! 3. Has a static wrapper method that takes `N+1` args (last is the delegate)
//!    and internally `callvirt`s the delegate's `Invoke()`
//!
//! The call pattern in SSA:
//!
//! ```text
//! v_delegate = LoadStaticField(singleton_field)
//! v_result   = Call(wrapper_method, arg0, arg1, ..., v_delegate)
//! ```
//!
//! By emulating delegate type `.cctor`s, the actual target method bound to
//! each delegate singleton is extracted and the indirect call is replaced
//! with a direct `Call` or `CallVirt`.
//!
//! # Detection
//!
//! Detection uses `detect_ssa()` to:
//! 1. Pre-scan assembly types for delegate types with static fields
//! 2. Verify wrapper methods via their SSA structure (follows def-use chains,
//!    immune to junk code insertions)
//! 3. Scan SSA functions for matching `LoadStaticField → Call(wrapper)` chains
//!
//! # Passes
//!
//! Creates a [`DelegateProxyResolutionPass`] with pre-computed findings from
//! detection, which emulates delegate `.cctor`s and resolves target methods.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use log::debug;

use crate::{
    analysis::{SsaFunction, SsaOp, SsaVarId},
    cilassembly::CleanupRequest,
    compiler::SsaPass,
    deobfuscation::{
        context::AnalysisContext,
        passes::{DelegateProxyResolutionPass, DelegateTypeInfo},
        techniques::PassPhase,
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from delegate proxy detection.
#[derive(Debug)]
pub struct DelegateProxyFindings {
    /// delegate_type_token → singleton field + wrapper method info.
    pub delegate_types: HashMap<Token, DelegateTypeInfo>,
    /// Method tokens containing at least one delegate proxy call.
    pub affected_methods: HashSet<Token>,
}

/// Traces a variable backwards through def-use chains to check if it
/// originates from a method argument.
///
/// Checks the variable's `VariableOrigin` directly (O(1) for argument vars),
/// and follows `Copy` and single-input `Phi` nodes for indirect references.
/// Limits traversal depth to prevent infinite loops.
fn traces_to_argument(ssa: &SsaFunction, var: SsaVarId) -> bool {
    let mut current = var;
    for _ in 0..20 {
        // Check the variable's origin — if it's an argument, we're done
        if let Some(variable) = ssa.variable(current) {
            if variable.origin().is_argument() {
                return true;
            }
        }

        // Check if defined by an instruction (Copy, LoadArg, etc.)
        if let Some(op) = ssa.get_definition(current) {
            match op {
                SsaOp::LoadArg { .. } => return true,
                SsaOp::Copy { src, .. } => {
                    current = *src;
                    continue;
                }
                _ => return false,
            }
        }

        // Check if defined by a phi node
        if let Some((_block_idx, phi)) = ssa.find_phi_defining(current) {
            let operands = phi.operands();
            if operands.len() == 1 {
                current = operands[0].value();
                continue;
            }
            return false;
        }

        return false;
    }
    false
}

/// Checks if a method's SSA matches the delegate wrapper pattern.
///
/// A wrapper method contains a `CallVirt` to an `Invoke` method where the
/// object (first arg) traces back to a `LoadArg`, meaning it receives the
/// delegate as a parameter and calls its `Invoke`. This is checked purely
/// via SSA def-use chains, making it immune to junk code insertions.
fn is_delegate_wrapper_ssa(ssa: &SsaFunction, assembly: &CilObject) -> bool {
    for block in ssa.blocks() {
        for instr in block.instructions() {
            let SsaOp::CallVirt { method, args, .. } = instr.op() else {
                continue;
            };

            // Check if the target method is "Invoke" on a delegate type
            let Some(method_name) = assembly.resolve_method_name(method.token()) else {
                continue;
            };
            if method_name != "Invoke" {
                continue;
            }

            // The first arg of CallVirt is the object (delegate instance).
            // It must trace back to a method argument — meaning the wrapper
            // receives the delegate as a parameter and calls its Invoke.
            let Some(&obj_var) = args.first() else {
                continue;
            };
            if traces_to_argument(ssa, obj_var) {
                return true;
            }
        }
    }
    false
}

/// Scans an SSA function for calls to known delegate wrapper methods.
///
/// Returns `true` if at least one `Call` instruction references a wrapper
/// method from the pre-computed set.
fn has_delegate_proxy_calls(ssa: &SsaFunction, wrapper_methods: &HashMap<Token, Token>) -> bool {
    for block in ssa.blocks() {
        for instr in block.instructions() {
            if let SsaOp::Call { method, .. } = instr.op() {
                if wrapper_methods.contains_key(&method.token()) {
                    return true;
                }
            }
        }
    }
    false
}

/// Detects delegate proxy call indirection via SSA analysis.
///
/// Identifies delegate types used as call proxies and the methods affected
/// by this pattern. Creates a [`DelegateProxyResolutionPass`] to resolve
/// indirect calls to their actual targets via emulation.
pub struct GenericDelegateProxy;

impl Technique for GenericDelegateProxy {
    fn id(&self) -> &'static str {
        "generic.delegates"
    }

    fn name(&self) -> &'static str {
        "Delegate Proxy Resolution"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Call
    }

    fn detect(&self, _assembly: &CilObject) -> Detection {
        // IL-level detection is not used — all detection happens in detect_ssa()
        // where we can follow exact def-use chains and verify wrapper patterns.
        Detection::new_empty()
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // Phase 1: Find delegate proxy types by scanning all types.
        //
        // A delegate proxy type:
        // - Inherits from System.MulticastDelegate (is_delegate())
        // - Has at least one static field (the singleton instance)
        // - Has a static wrapper method whose SSA contains CallVirt(Invoke)
        //   where the delegate object comes from a LoadArg parameter
        let mut delegate_types: HashMap<Token, DelegateTypeInfo> = HashMap::new();
        let mut wrapper_to_delegate: HashMap<Token, Token> = HashMap::new();

        let mut delegate_count = 0usize;
        let mut has_static_field = 0usize;
        let mut has_static_method = 0usize;
        let mut has_ssa = 0usize;
        let mut is_wrapper = 0usize;

        for type_entry in assembly.types().iter() {
            let ty = type_entry.value();
            if !ty.is_delegate() {
                continue;
            }
            delegate_count += 1;

            // Find the singleton static field. Delegate types normally have no
            // static fields, so any static field is the singleton instance.
            let Some(singleton_field_token) = ty
                .fields
                .iter()
                .find(|(_, f)| f.flags.is_static())
                .map(|(_, f)| f.token)
            else {
                continue;
            };
            has_static_field += 1;

            // Find the wrapper method: static (not .cctor/.ctor), whose SSA
            // shows a CallVirt(Invoke) pattern with the delegate from a parameter.
            let wrapper_method_token = ty.methods.iter().find_map(|(_, method_ref)| {
                let method = method_ref.upgrade()?;
                if !method.is_static() || method.is_cctor() || method.is_ctor() {
                    return None;
                }
                has_static_method += 1;

                // Look up this method's SSA function from the analysis context
                let ssa_ref = ctx.ssa_functions.get(&method.token);
                if ssa_ref.is_none() {
                    debug!(
                        "Delegate detect: type {}.{} method 0x{:08X} ({}) has no SSA",
                        ty.namespace, ty.name, method.token.value(), method.name
                    );
                    return None;
                }
                has_ssa += 1;

                let ssa = ssa_ref.unwrap();
                if is_delegate_wrapper_ssa(ssa.value(), assembly) {
                    is_wrapper += 1;
                    Some(method.token)
                } else {
                    debug!(
                        "Delegate detect: type {}.{} method 0x{:08X} ({}) SSA did not match wrapper pattern",
                        ty.namespace, ty.name, method.token.value(), method.name
                    );
                    None
                }
            });

            let Some(wrapper_method_token) = wrapper_method_token else {
                continue;
            };

            delegate_types.insert(
                ty.token,
                DelegateTypeInfo {
                    singleton_field_token,
                    wrapper_method_token,
                },
            );
            wrapper_to_delegate.insert(wrapper_method_token, ty.token);
        }

        debug!(
            "Delegate detect: {} delegate types, {} with static fields, {} with static methods, {} with SSA, {} matched wrapper pattern",
            delegate_count, has_static_field, has_static_method, has_ssa, is_wrapper
        );

        if delegate_types.is_empty() {
            return Detection::new_empty();
        }

        // Phase 2: Scan SSA functions for Call sites targeting wrapper methods.
        let mut affected_methods: HashSet<Token> = HashSet::new();

        for entry in ctx.ssa_functions.iter() {
            let method_token = *entry.key();
            let ssa = entry.value();

            if has_delegate_proxy_calls(ssa, &wrapper_to_delegate) {
                affected_methods.insert(method_token);
            }
        }

        if affected_methods.is_empty() {
            return Detection::new_empty();
        }

        let type_count = delegate_types.len();
        let method_count = affected_methods.len();

        let evidence = vec![Evidence::Structural(format!(
            "{type_count} delegate proxy types affecting {method_count} methods"
        ))];

        let findings = DelegateProxyFindings {
            delegate_types,
            affected_methods,
        };

        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Inline)
    }

    fn create_pass(
        &self,
        ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Option<Box<dyn SsaPass>> {
        let pool = ctx.template_pool.get()?.clone();
        let findings = detection.findings::<DelegateProxyFindings>()?;
        Some(Box::new(DelegateProxyResolutionPass::new(
            pool,
            findings.delegate_types.clone(),
            findings.affected_methods.clone(),
        )))
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<DelegateProxyFindings>()?;
        if findings.delegate_types.is_empty() {
            return None;
        }

        let mut request = CleanupRequest::new();
        for &type_token in findings.delegate_types.keys() {
            request.add_type(type_token);
        }
        Some(request)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            generic::delegates::{DelegateProxyFindings, GenericDelegateProxy},
            PassPhase, Technique, TechniqueCategory,
        },
        test::helpers::load_sample,
    };

    #[test]
    fn test_detect_negative_confuserex_original() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = GenericDelegateProxy;
        let detection = technique.detect(&asm);

        assert!(
            !detection.detected,
            "GenericDelegateProxy should not detect anything in a ConfuserEx original sample"
        );
        assert!(
            detection.evidence.is_empty(),
            "No evidence should be present for a non-obfuscated sample"
        );
        assert!(
            detection.findings::<DelegateProxyFindings>().is_none(),
            "No findings should be present for a non-obfuscated sample"
        );
    }

    #[test]
    fn test_detect_negative_obfuscar_sample() {
        let asm = load_sample("tests/samples/packers/obfuscar/2.2.50/obfuscar_strings_only.exe");

        let technique = GenericDelegateProxy;
        let detection = technique.detect(&asm);

        assert!(
            !detection.detected,
            "GenericDelegateProxy should not detect anything in an Obfuscar sample"
        );
    }

    #[test]
    fn test_technique_metadata() {
        let technique = GenericDelegateProxy;
        assert_eq!(technique.id(), "generic.delegates");
        assert_eq!(technique.name(), "Delegate Proxy Resolution");
        assert_eq!(technique.category(), TechniqueCategory::Call);
        assert!(technique.supersedes().is_empty());
    }

    #[test]
    fn test_technique_ssa_phase() {
        let technique = GenericDelegateProxy;
        assert_eq!(
            technique.ssa_phase(),
            Some(PassPhase::Inline),
            "GenericDelegateProxy should run in the Inline SSA phase"
        );
    }
}
