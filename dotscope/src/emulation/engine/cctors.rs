//! Static constructor (.cctor) failure tracking.
//!
//! Per ECMA-335, when a type's static constructor throws an unhandled
//! exception, the CLR:
//! 1. Wraps it in a `TypeInitializationException`
//! 2. Marks the type as permanently failed
//! 3. Re-throws the same `TypeInitializationException` on subsequent access
//!
//! This module tracks which types have failed initialization and stores
//! the exception reference so it can be re-thrown on every subsequent
//! attempt to use the type.

use std::sync::RwLock;

use imbl::HashMap as ImHashMap;

use crate::{
    emulation::{engine::EmulationError, HeapRef},
    metadata::token::Token,
};

/// Tracks types whose static constructors have failed.
///
/// Thread-safe via `RwLock`; supports `fork()` for copy-on-write semantics.
#[derive(Debug)]
pub struct CctorTracker {
    /// Map of type token → heap reference of the stored exception.
    failed_types: RwLock<ImHashMap<Token, HeapRef>>,
}

impl CctorTracker {
    /// Creates a new empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            failed_types: RwLock::new(ImHashMap::new()),
        }
    }

    /// Records that a type's .cctor failed with the given exception.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal lock is poisoned.
    pub fn mark_type_failed(
        &self,
        type_token: Token,
        exception_ref: HeapRef,
    ) -> Result<(), EmulationError> {
        let mut map = self
            .failed_types
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "cctor tracker",
            })?;
        map.insert(type_token, exception_ref);
        Ok(())
    }

    /// Returns the stored exception if the type's .cctor has previously failed.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal lock is poisoned.
    pub fn get_type_failure(&self, type_token: Token) -> Result<Option<HeapRef>, EmulationError> {
        let map = self
            .failed_types
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "cctor tracker",
            })?;
        Ok(map.get(&type_token).copied())
    }

    /// Creates an independent copy of this tracker (O(1) via structural sharing).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal lock is poisoned.
    pub fn fork(&self) -> Result<Self, EmulationError> {
        let map = self
            .failed_types
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "cctor tracker",
            })?;
        Ok(Self {
            failed_types: RwLock::new(map.clone()),
        })
    }
}

impl Default for CctorTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{engine::cctors::CctorTracker, HeapRef},
        metadata::token::Token,
    };

    #[test]
    fn test_initial_state_has_no_failures() {
        let tracker = CctorTracker::new();
        assert!(tracker
            .get_type_failure(Token::new(0x0200_0001))
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_mark_and_retrieve_failure() {
        let tracker = CctorTracker::new();
        let type_token = Token::new(0x0200_0001);
        let exception_ref = HeapRef::new(42);

        tracker.mark_type_failed(type_token, exception_ref).unwrap();

        assert_eq!(
            tracker.get_type_failure(type_token).unwrap(),
            Some(exception_ref)
        );
    }

    #[test]
    fn test_repeated_access_returns_same_exception() {
        let tracker = CctorTracker::new();
        let type_token = Token::new(0x0200_0001);
        let exception_ref = HeapRef::new(99);

        tracker.mark_type_failed(type_token, exception_ref).unwrap();

        assert_eq!(
            tracker.get_type_failure(type_token).unwrap(),
            Some(exception_ref)
        );
        assert_eq!(
            tracker.get_type_failure(type_token).unwrap(),
            Some(exception_ref)
        );
    }

    #[test]
    fn test_different_types_independent() {
        let tracker = CctorTracker::new();
        let type_a = Token::new(0x0200_0001);
        let type_b = Token::new(0x0200_0002);
        let exc_a = HeapRef::new(10);
        let exc_b = HeapRef::new(20);

        tracker.mark_type_failed(type_a, exc_a).unwrap();
        tracker.mark_type_failed(type_b, exc_b).unwrap();

        assert_eq!(tracker.get_type_failure(type_a).unwrap(), Some(exc_a));
        assert_eq!(tracker.get_type_failure(type_b).unwrap(), Some(exc_b));
    }

    #[test]
    fn test_fork_preserves_failures() {
        let tracker = CctorTracker::new();
        let type_token = Token::new(0x0200_0001);
        let exception_ref = HeapRef::new(42);

        tracker.mark_type_failed(type_token, exception_ref).unwrap();

        let forked = tracker.fork().unwrap();
        assert_eq!(
            forked.get_type_failure(type_token).unwrap(),
            Some(exception_ref)
        );
    }

    #[test]
    fn test_fork_is_independent() {
        let tracker = CctorTracker::new();
        let type_a = Token::new(0x0200_0001);
        let type_b = Token::new(0x0200_0002);
        let exc_a = HeapRef::new(10);
        let exc_b = HeapRef::new(20);

        tracker.mark_type_failed(type_a, exc_a).unwrap();
        let forked = tracker.fork().unwrap();

        // Add to forked only
        forked.mark_type_failed(type_b, exc_b).unwrap();

        // Original should not see type_b
        assert!(tracker.get_type_failure(type_b).unwrap().is_none());
        // Forked should see both
        assert_eq!(forked.get_type_failure(type_a).unwrap(), Some(exc_a));
        assert_eq!(forked.get_type_failure(type_b).unwrap(), Some(exc_b));
    }
}
