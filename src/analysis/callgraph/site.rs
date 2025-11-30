//! Call site representation and call target types.
//!
//! This module defines the types used to represent individual call instructions
//! and their resolved targets within the call graph.

use crate::metadata::token::Token;

/// Type of call instruction.
///
/// Represents the different CIL opcodes that can invoke methods, ranging from
/// direct calls to virtual dispatch and indirect function pointer invocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallType {
    /// Direct call instruction (`call`).
    Call,
    /// Virtual call instruction (`callvirt`).
    CallVirt,
    /// Tail call (`tail.call` or `tail.callvirt`).
    TailCall,
    /// Object construction (`newobj`).
    NewObj,
    /// Indirect call through function pointer (`calli`).
    Calli,
    /// Load function pointer (`ldftn`).
    Ldftn,
    /// Load virtual function pointer (`ldvirtftn`).
    LdVirtFtn,
}

impl CallType {
    /// Returns `true` if this is a virtual call that requires runtime dispatch.
    ///
    /// Virtual calls use the actual runtime type of the receiver object to
    /// determine the method implementation to invoke.
    ///
    /// # Returns
    ///
    /// `true` for `CallVirt` and `LdVirtFtn` call types, `false` otherwise.
    #[must_use]
    pub const fn is_virtual(&self) -> bool {
        matches!(self, Self::CallVirt | Self::LdVirtFtn)
    }

    /// Returns `true` if this is an indirect call through a function pointer.
    ///
    /// Indirect calls invoke a method through a computed address rather than
    /// a statically resolved method token.
    ///
    /// # Returns
    ///
    /// `true` for `Calli` call type, `false` otherwise.
    #[must_use]
    pub const fn is_indirect(&self) -> bool {
        matches!(self, Self::Calli)
    }

    /// Returns `true` if this call creates a new object.
    ///
    /// Constructor calls allocate a new object and invoke its constructor.
    ///
    /// # Returns
    ///
    /// `true` for `NewObj` call type, `false` otherwise.
    #[must_use]
    pub const fn is_constructor(&self) -> bool {
        matches!(self, Self::NewObj)
    }
}

/// Resolved target of a call instruction.
///
/// Represents the outcome of call target resolution, which may be a single
/// resolved method, multiple possible targets (for virtual calls), or various
/// unresolved states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallTarget {
    /// Resolved to a specific method in the current assembly.
    Resolved(Token),

    /// Virtual call with multiple possible targets from Class Hierarchy Analysis.
    Virtual {
        /// The declared method being called.
        declared: Token,
        /// All possible runtime targets (including overrides).
        possible_targets: Vec<Token>,
    },

    /// Call to an external method (different assembly).
    External {
        /// The assembly reference name.
        assembly: String,
        /// The full method signature string.
        method: String,
    },

    /// Delegate or function pointer invocation.
    Delegate {
        /// The delegate type token (if known).
        delegate_type: Option<Token>,
    },

    /// Indirect call through computed function pointer.
    Indirect,

    /// Target could not be resolved.
    Unresolved {
        /// The original token that couldn't be resolved.
        token: Token,
        /// Reason for resolution failure.
        reason: String,
    },
}

impl CallTarget {
    /// Returns `true` if this target was successfully resolved.
    ///
    /// A target is considered resolved if we know what method(s) could be
    /// invoked at runtime, even if there are multiple possibilities.
    ///
    /// # Returns
    ///
    /// `true` for `Resolved`, `Virtual`, and `External` variants, `false` otherwise.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        matches!(
            self,
            Self::Resolved(_) | Self::Virtual { .. } | Self::External { .. }
        )
    }

    /// Returns the primary target token, if available.
    ///
    /// For resolved calls, returns the method token. For virtual calls, returns
    /// the declared method token. For unresolved calls, returns the original
    /// token that couldn't be resolved.
    ///
    /// # Returns
    ///
    /// - `Some(token)` for `Resolved`, `Virtual`, and `Unresolved` variants
    /// - `None` for `External`, `Delegate`, and `Indirect` variants
    #[must_use]
    pub fn primary_token(&self) -> Option<Token> {
        match self {
            Self::Resolved(token) => Some(*token),
            Self::Virtual { declared, .. } => Some(*declared),
            Self::Unresolved { token, .. } => Some(*token),
            _ => None,
        }
    }

    /// Returns all possible target tokens for this call.
    ///
    /// For resolved calls, returns a single-element vector. For virtual calls,
    /// returns all possible runtime targets determined by Class Hierarchy Analysis.
    ///
    /// # Returns
    ///
    /// A vector of method tokens. Empty for `External`, `Delegate`, `Indirect`,
    /// and `Unresolved` variants.
    #[must_use]
    pub fn all_targets(&self) -> Vec<Token> {
        match self {
            Self::Resolved(token) => vec![*token],
            Self::Virtual {
                possible_targets, ..
            } => possible_targets.clone(),
            _ => Vec::new(),
        }
    }
}

/// A specific call instruction within a method body.
///
/// Represents a single call site, including its location (IL offset), the type
/// of call instruction, and the resolved target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    /// IL offset of the call instruction within the method body.
    pub offset: u32,
    /// Type of call instruction.
    pub call_type: CallType,
    /// Resolved target of the call.
    pub target: CallTarget,
}

impl CallSite {
    /// Creates a new call site.
    ///
    /// # Arguments
    ///
    /// * `offset` - The IL offset of the call instruction within the method body
    /// * `call_type` - The type of call instruction (call, callvirt, etc.)
    /// * `target` - The resolved target of the call
    ///
    /// # Returns
    ///
    /// A new `CallSite` instance with the specified properties.
    #[must_use]
    pub const fn new(offset: u32, call_type: CallType, target: CallTarget) -> Self {
        Self {
            offset,
            call_type,
            target,
        }
    }

    /// Returns `true` if this call may have multiple runtime targets.
    ///
    /// A polymorphic call site is a virtual call where Class Hierarchy Analysis
    /// determined that multiple method implementations could be invoked at runtime.
    ///
    /// # Returns
    ///
    /// `true` if the call target has more than one possible implementation,
    /// `false` otherwise.
    #[must_use]
    pub fn is_polymorphic(&self) -> bool {
        matches!(
            &self.target,
            CallTarget::Virtual {
                possible_targets, ..
            } if possible_targets.len() > 1
        )
    }

    /// Returns `true` if the call target is fully resolved.
    ///
    /// # Returns
    ///
    /// `true` if we know what method(s) could be invoked, `false` for unresolved
    /// or indirect calls.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.target.is_resolved()
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::callgraph::{CallSite, CallTarget, CallType};
    use crate::metadata::token::Token;

    #[test]
    fn test_call_type_properties() {
        assert!(!CallType::Call.is_virtual());
        assert!(CallType::CallVirt.is_virtual());
        assert!(CallType::LdVirtFtn.is_virtual());
        assert!(!CallType::Calli.is_virtual());

        assert!(!CallType::Call.is_indirect());
        assert!(CallType::Calli.is_indirect());

        assert!(!CallType::Call.is_constructor());
        assert!(CallType::NewObj.is_constructor());
    }

    #[test]
    fn test_call_target_resolved() {
        let token = Token::new(0x0600_0001);
        let resolved = CallTarget::Resolved(token);
        assert!(resolved.is_resolved());
        assert_eq!(resolved.primary_token(), Some(token));
        assert_eq!(resolved.all_targets(), vec![token]);
    }

    #[test]
    fn test_call_target_virtual() {
        let declared = Token::new(0x0600_0001);
        let target1 = Token::new(0x0600_0002);
        let target2 = Token::new(0x0600_0003);
        let virtual_target = CallTarget::Virtual {
            declared,
            possible_targets: vec![target1, target2],
        };

        assert!(virtual_target.is_resolved());
        assert_eq!(virtual_target.primary_token(), Some(declared));
        assert_eq!(virtual_target.all_targets(), vec![target1, target2]);
    }

    #[test]
    fn test_call_target_external() {
        let external = CallTarget::External {
            assembly: "mscorlib".to_string(),
            method: "System.Console::WriteLine".to_string(),
        };
        assert!(external.is_resolved());
        assert_eq!(external.primary_token(), None);
        assert!(external.all_targets().is_empty());
    }

    #[test]
    fn test_call_target_unresolved() {
        let token = Token::new(0x0A00_0001);
        let unresolved = CallTarget::Unresolved {
            token,
            reason: "External assembly not loaded".to_string(),
        };
        assert!(!unresolved.is_resolved());
        assert_eq!(unresolved.primary_token(), Some(token));
    }

    #[test]
    fn test_call_site_polymorphic() {
        let declared = Token::new(0x0600_0001);

        // Single target - not polymorphic
        let single = CallSite::new(
            0,
            CallType::CallVirt,
            CallTarget::Virtual {
                declared,
                possible_targets: vec![declared],
            },
        );
        assert!(!single.is_polymorphic());

        // Multiple targets - polymorphic
        let multiple = CallSite::new(
            0,
            CallType::CallVirt,
            CallTarget::Virtual {
                declared,
                possible_targets: vec![declared, Token::new(0x0600_0002)],
            },
        );
        assert!(multiple.is_polymorphic());

        // Direct call - not polymorphic
        let direct = CallSite::new(0, CallType::Call, CallTarget::Resolved(declared));
        assert!(!direct.is_polymorphic());
    }
}
