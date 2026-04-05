//! Processing state for dirty tracking and fixpoint iteration.
//!
//! The [`ProcessingState`] tracks which methods and types need processing,
//! which have stabilized, and whether assembly-wide re-analysis is needed.
//! All fields use concurrent data structures for safe access from rayon threads.

use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashSet;

use crate::metadata::token::Token;

/// Tracks processing state for methods, types, and the assembly during
/// the deobfuscation fixpoint loop.
///
/// State transitions:
/// - Methods: `dirty` → (pass runs) → `stable` or `needs_ssa_build`
/// - SSA build: `needs_ssa_build` → (build) → `dirty`
/// - Types: `type_dirty` → (pass runs) → `type_stable`
pub struct ProcessingState {
    /// Methods needing SSA (re)construction before passes can process them.
    pub needs_ssa_build: DashSet<Token>,
    /// Methods that have been modified and need reprocessing.
    pub method_dirty: DashSet<Token>,
    /// Methods that have reached fixpoint (no changes in last pass iteration).
    pub method_stable: DashSet<Token>,
    /// Tokens discovered during re-detection that need processing.
    pub newly_detected: DashSet<Token>,
    /// Types with modified members that need reprocessing.
    pub type_dirty: DashSet<Token>,
    /// Types that have reached fixpoint.
    pub type_stable: DashSet<Token>,
    /// Assembly-wide dirty flag for global re-analysis.
    assembly_dirty: AtomicBool,
}

impl ProcessingState {
    /// Creates a new empty processing state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            needs_ssa_build: DashSet::new(),
            method_dirty: DashSet::new(),
            method_stable: DashSet::new(),
            newly_detected: DashSet::new(),
            type_dirty: DashSet::new(),
            type_stable: DashSet::new(),
            assembly_dirty: AtomicBool::new(false),
        }
    }

    /// Creates a processing state where all given methods start as dirty.
    #[must_use]
    pub fn from_methods(methods: impl IntoIterator<Item = Token>) -> Self {
        let state = Self::new();
        for token in methods {
            state.method_dirty.insert(token);
        }
        state
    }

    /// Marks a method as dirty (needing reprocessing).
    ///
    /// Removes the method from the stable set if present.
    pub fn mark_method_dirty(&self, token: Token) {
        self.method_stable.remove(&token);
        self.method_dirty.insert(token);
    }

    /// Marks a method as stable (reached fixpoint).
    ///
    /// Removes the method from the dirty set if present.
    pub fn mark_method_stable(&self, token: Token) {
        self.method_dirty.remove(&token);
        self.method_stable.insert(token);
    }

    /// Marks a method as needing SSA (re)construction.
    ///
    /// Removes the method from both dirty and stable sets.
    pub fn mark_needs_ssa_build(&self, token: Token) {
        self.method_dirty.remove(&token);
        self.method_stable.remove(&token);
        self.needs_ssa_build.insert(token);
    }

    /// Marks a method's SSA as built, transitioning it to dirty for pass processing.
    ///
    /// Removes the method from the needs_ssa_build set.
    pub fn mark_ssa_built(&self, token: Token) {
        self.needs_ssa_build.remove(&token);
        self.method_dirty.insert(token);
    }

    /// Marks a type as dirty (has modified members).
    ///
    /// Removes the type from the stable set if present.
    pub fn mark_type_dirty(&self, token: Token) {
        self.type_stable.remove(&token);
        self.type_dirty.insert(token);
    }

    /// Marks a type as stable (reached fixpoint).
    ///
    /// Removes the type from the dirty set if present.
    pub fn mark_type_stable(&self, token: Token) {
        self.type_dirty.remove(&token);
        self.type_stable.insert(token);
    }

    /// Sets the assembly-wide dirty flag.
    pub fn mark_assembly_dirty(&self) {
        self.assembly_dirty.store(true, Ordering::Release);
    }

    /// Clears the assembly-wide dirty flag.
    pub fn clear_assembly_dirty(&self) {
        self.assembly_dirty.store(false, Ordering::Release);
    }

    /// Returns `true` if the assembly-wide dirty flag is set.
    #[must_use]
    pub fn is_assembly_dirty(&self) -> bool {
        self.assembly_dirty.load(Ordering::Acquire)
    }

    /// Returns `true` if there is any pending work (dirty methods/types,
    /// SSA builds needed, newly detected tokens, or assembly dirty).
    #[must_use]
    pub fn has_pending_work(&self) -> bool {
        !self.method_dirty.is_empty()
            || !self.needs_ssa_build.is_empty()
            || !self.newly_detected.is_empty()
            || !self.type_dirty.is_empty()
            || self.is_assembly_dirty()
    }

    /// Returns the number of dirty methods.
    #[must_use]
    pub fn dirty_method_count(&self) -> usize {
        self.method_dirty.len()
    }

    /// Returns the number of stable methods.
    #[must_use]
    pub fn stable_method_count(&self) -> usize {
        self.method_stable.len()
    }
}

impl Default for ProcessingState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{compiler::state::ProcessingState, metadata::token::Token};

    #[test]
    fn test_from_methods() {
        let tokens: Vec<Token> = (1..=5).map(|i| Token::new(0x06000000 + i)).collect();
        let state = ProcessingState::from_methods(tokens.clone());

        for token in &tokens {
            assert!(state.method_dirty.contains(token));
            assert!(!state.method_stable.contains(token));
        }
        assert_eq!(state.dirty_method_count(), 5);
        assert_eq!(state.stable_method_count(), 0);
    }

    #[test]
    fn test_mark_dirty_removes_stable() {
        let state = ProcessingState::new();
        let token = Token::new(0x06000001);

        // Start stable
        state.mark_method_stable(token);
        assert!(state.method_stable.contains(&token));
        assert!(!state.method_dirty.contains(&token));

        // Mark dirty should remove from stable
        state.mark_method_dirty(token);
        assert!(state.method_dirty.contains(&token));
        assert!(!state.method_stable.contains(&token));
    }

    #[test]
    fn test_mark_stable_removes_dirty() {
        let state = ProcessingState::new();
        let token = Token::new(0x06000001);

        // Start dirty
        state.mark_method_dirty(token);
        assert!(state.method_dirty.contains(&token));

        // Mark stable should remove from dirty
        state.mark_method_stable(token);
        assert!(state.method_stable.contains(&token));
        assert!(!state.method_dirty.contains(&token));
    }

    #[test]
    fn test_needs_ssa_build_clears_both() {
        let state = ProcessingState::new();
        let token = Token::new(0x06000001);

        // Put in both dirty and stable (shouldn't happen normally, but tests the clearing)
        state.method_dirty.insert(token);
        state.method_stable.insert(token);

        state.mark_needs_ssa_build(token);
        assert!(state.needs_ssa_build.contains(&token));
        assert!(!state.method_dirty.contains(&token));
        assert!(!state.method_stable.contains(&token));
    }

    #[test]
    fn test_ssa_built_transitions_to_dirty() {
        let state = ProcessingState::new();
        let token = Token::new(0x06000001);

        state.mark_needs_ssa_build(token);
        assert!(state.needs_ssa_build.contains(&token));

        state.mark_ssa_built(token);
        assert!(!state.needs_ssa_build.contains(&token));
        assert!(state.method_dirty.contains(&token));
    }

    #[test]
    fn test_type_transitions() {
        let state = ProcessingState::new();
        let token = Token::new(0x02000001);

        // dirty → stable
        state.mark_type_dirty(token);
        assert!(state.type_dirty.contains(&token));
        assert!(!state.type_stable.contains(&token));

        state.mark_type_stable(token);
        assert!(!state.type_dirty.contains(&token));
        assert!(state.type_stable.contains(&token));

        // stable → dirty
        state.mark_type_dirty(token);
        assert!(state.type_dirty.contains(&token));
        assert!(!state.type_stable.contains(&token));
    }

    #[test]
    fn test_assembly_dirty_flag() {
        let state = ProcessingState::new();

        assert!(!state.is_assembly_dirty());

        state.mark_assembly_dirty();
        assert!(state.is_assembly_dirty());

        state.clear_assembly_dirty();
        assert!(!state.is_assembly_dirty());
    }

    #[test]
    fn test_has_pending_work() {
        let state = ProcessingState::new();
        assert!(!state.has_pending_work());

        // Dirty method triggers pending work
        state.mark_method_dirty(Token::new(0x06000001));
        assert!(state.has_pending_work());

        // Clear dirty, should have no pending work
        state.mark_method_stable(Token::new(0x06000001));
        assert!(!state.has_pending_work());

        // needs_ssa_build triggers pending work
        state.mark_needs_ssa_build(Token::new(0x06000002));
        assert!(state.has_pending_work());

        // Clear it
        state.mark_ssa_built(Token::new(0x06000002));
        // Now it's dirty again, still pending
        assert!(state.has_pending_work());
        state.mark_method_stable(Token::new(0x06000002));
        assert!(!state.has_pending_work());

        // newly_detected triggers pending work
        state.newly_detected.insert(Token::new(0x06000003));
        assert!(state.has_pending_work());
        state.newly_detected.remove(&Token::new(0x06000003));
        assert!(!state.has_pending_work());

        // type_dirty triggers pending work
        state.mark_type_dirty(Token::new(0x02000001));
        assert!(state.has_pending_work());
        state.mark_type_stable(Token::new(0x02000001));
        assert!(!state.has_pending_work());

        // assembly_dirty triggers pending work
        state.mark_assembly_dirty();
        assert!(state.has_pending_work());
        state.clear_assembly_dirty();
        assert!(!state.has_pending_work());
    }

    #[test]
    fn test_new_is_empty() {
        let state = ProcessingState::new();

        assert!(!state.has_pending_work());
        assert_eq!(state.dirty_method_count(), 0);
        assert_eq!(state.stable_method_count(), 0);
        assert!(state.needs_ssa_build.is_empty());
        assert!(state.newly_detected.is_empty());
        assert!(state.type_dirty.is_empty());
        assert!(state.type_stable.is_empty());
        assert!(!state.is_assembly_dirty());
    }
}
