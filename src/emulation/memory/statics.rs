//! Static field storage for CIL emulation.
//!
//! This module provides [`StaticFieldStorage`] for managing static (class-level)
//! fields during CIL bytecode execution. Static fields are accessed via
//! `ldsfld` and `stsfld` instructions.
//!
//! # Static Field Semantics
//!
//! Static fields are shared across all instances of a type and persist for
//! the lifetime of the emulated process. They are initialized when first
//! accessed or when the type's static constructor (`.cctor`) is run.
//!
//! # Thread Safety
//!
//! All operations use interior mutability via `RwLock` for thread-safe access.
//!
//! # Copy-on-Write Semantics
//!
//! The storage uses `imbl::HashMap` and `imbl::HashSet` for O(1) fork operations.
//! When you call `fork()`, both the original and the fork share the same underlying
//! data structure via structural sharing. Only modified entries are copied.
//!
//! # Type Initialization Tracking
//!
//! The storage tracks which types have had their static constructors run via
//! [`is_type_initialized`](StaticFieldStorage::is_type_initialized) and
//! [`mark_type_initialized`](StaticFieldStorage::mark_type_initialized).

use std::sync::RwLock;

use imbl::{HashMap as ImHashMap, HashSet as ImHashSet};

use crate::{emulation::EmValue, metadata::token::Token};

/// Storage for static fields in the emulated process.
///
/// Static fields are stored by their field token and persist across method
/// calls and thread boundaries. This structure also tracks which types have
/// had their static constructors (`.cctor`) executed.
///
/// # Thread Safety
///
/// All operations use interior mutability via `RwLock`, allowing safe
/// concurrent access from multiple threads.
///
/// # Copy-on-Write
///
/// The storage uses `imbl` persistent data structures internally, enabling
/// O(1) `fork()` operations via structural sharing.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::{StaticFieldStorage, EmValue};
/// use dotscope::metadata::token::Token;
///
/// let storage = StaticFieldStorage::new();
///
/// // Store a static field
/// let field_token = Token::new(0x04000001);
/// storage.set(field_token, EmValue::I32(42));
///
/// // Retrieve it later
/// assert_eq!(storage.get(field_token), Some(EmValue::I32(42)));
///
/// // Fork creates an independent copy (O(1) operation!)
/// let forked = storage.fork();
/// forked.set(field_token, EmValue::I32(100));
/// // Original is unchanged
/// assert_eq!(storage.get(field_token), Some(EmValue::I32(42)));
/// ```
#[derive(Debug)]
pub struct StaticFieldStorage {
    /// Static fields indexed by field token.
    /// Uses imbl::HashMap for O(1) fork via structural sharing.
    fields: RwLock<ImHashMap<Token, EmValue>>,

    /// Tracks which types have had their static constructors run.
    /// Uses imbl::HashSet for O(1) fork via structural sharing.
    initialized_types: RwLock<ImHashSet<Token>>,
}

impl StaticFieldStorage {
    /// Creates new empty static field storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fields: RwLock::new(ImHashMap::new()),
            initialized_types: RwLock::new(ImHashSet::new()),
        }
    }

    /// Gets a static field value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    ///
    /// # Returns
    ///
    /// `Some(EmValue)` if the field exists, `None` otherwise.
    #[must_use]
    pub fn get(&self, field_token: Token) -> Option<EmValue> {
        let fields = self.fields.read().expect("fields lock poisoned");
        fields.get(&field_token).cloned()
    }

    /// Sets a static field value.
    ///
    /// If the field already exists, its value is replaced.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    /// * `value` - The value to store
    pub fn set(&self, field_token: Token, value: EmValue) {
        let mut fields = self.fields.write().expect("fields lock poisoned");
        fields.insert(field_token, value);
    }

    /// Returns `true` if the static field exists.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    #[must_use]
    pub fn contains(&self, field_token: Token) -> bool {
        let fields = self.fields.read().expect("fields lock poisoned");
        fields.contains_key(&field_token)
    }

    /// Removes a static field and returns its value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field
    ///
    /// # Returns
    ///
    /// The removed value, or `None` if the field didn't exist.
    pub fn remove(&self, field_token: Token) -> Option<EmValue> {
        let mut fields = self.fields.write().expect("fields lock poisoned");
        fields.remove(&field_token)
    }

    /// Returns `true` if the type's static constructor has been run.
    ///
    /// This is used to implement the `.cctor` execution semantics where
    /// static constructors run at most once per type.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type's metadata token
    #[must_use]
    pub fn is_type_initialized(&self, type_token: Token) -> bool {
        let initialized = self
            .initialized_types
            .read()
            .expect("initialized lock poisoned");
        initialized.contains(&type_token)
    }

    /// Marks a type as having had its static constructor run.
    ///
    /// Call this after successfully executing a type's `.cctor` method.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type's metadata token
    pub fn mark_type_initialized(&self, type_token: Token) {
        let mut initialized = self
            .initialized_types
            .write()
            .expect("initialized lock poisoned");
        initialized.insert(type_token);
    }

    /// Clears all static fields and initialization state.
    ///
    /// This resets the storage to its initial empty state, useful for
    /// testing or resetting the emulator.
    pub fn clear(&self) {
        let mut fields = self.fields.write().expect("fields lock poisoned");
        let mut initialized = self
            .initialized_types
            .write()
            .expect("initialized lock poisoned");
        fields.clear();
        initialized.clear();
    }

    /// Returns the number of static fields stored.
    #[must_use]
    pub fn len(&self) -> usize {
        let fields = self.fields.read().expect("fields lock poisoned");
        fields.len()
    }

    /// Returns `true` if no static fields are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let fields = self.fields.read().expect("fields lock poisoned");
        fields.is_empty()
    }

    /// Returns all stored field tokens.
    ///
    /// Useful for debugging and diagnostics.
    #[must_use]
    pub fn field_tokens(&self) -> Vec<Token> {
        let fields = self.fields.read().expect("fields lock poisoned");
        fields.keys().copied().collect()
    }

    /// Returns all type tokens that have been marked as initialized.
    ///
    /// Useful for debugging and diagnostics.
    #[must_use]
    pub fn initialized_types(&self) -> Vec<Token> {
        let initialized = self
            .initialized_types
            .read()
            .expect("initialized lock poisoned");
        initialized.iter().copied().collect()
    }

    /// Forks this storage, creating an independent copy with CoW semantics.
    ///
    /// The forked storage shares its data structure with the original via
    /// structural sharing. Both storages can be modified independently -
    /// only the modified entries are copied (true copy-on-write).
    ///
    /// # Performance
    ///
    /// This is an O(1) operation due to `imbl`'s structural sharing.
    /// The actual data is only copied when either storage modifies an entry.
    #[must_use]
    pub fn fork(&self) -> Self {
        let fields = self.fields.read().expect("fields lock poisoned");
        let initialized = self
            .initialized_types
            .read()
            .expect("initialized lock poisoned");
        Self {
            // imbl::HashMap::clone() and imbl::HashSet::clone() are O(1) - structural sharing!
            fields: RwLock::new(fields.clone()),
            initialized_types: RwLock::new(initialized.clone()),
        }
    }
}

impl Default for StaticFieldStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for StaticFieldStorage {
    fn clone(&self) -> Self {
        // Clone is the same as fork - O(1) due to imbl's structural sharing
        self.fork()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{memory::statics::StaticFieldStorage, EmValue},
        metadata::token::Token,
    };

    #[test]
    fn test_static_field_storage() {
        let storage = StaticFieldStorage::new();
        let field = Token::new(0x04000001);

        // Initially empty
        assert!(storage.get(field).is_none());
        assert!(!storage.contains(field));

        // Set a value
        storage.set(field, EmValue::I32(42));
        assert!(storage.contains(field));
        assert_eq!(storage.get(field), Some(EmValue::I32(42)));

        // Update the value
        storage.set(field, EmValue::I32(100));
        assert_eq!(storage.get(field), Some(EmValue::I32(100)));

        // Remove
        let removed = storage.remove(field);
        assert_eq!(removed, Some(EmValue::I32(100)));
        assert!(storage.get(field).is_none());
    }

    #[test]
    fn test_type_initialization_tracking() {
        let storage = StaticFieldStorage::new();
        let type_token = Token::new(0x02000001);

        // Initially not initialized
        assert!(!storage.is_type_initialized(type_token));

        // Mark as initialized
        storage.mark_type_initialized(type_token);
        assert!(storage.is_type_initialized(type_token));

        // Check we can get the list
        let initialized = storage.initialized_types();
        assert!(initialized.contains(&type_token));
    }

    #[test]
    fn test_clear() {
        let storage = StaticFieldStorage::new();
        let field = Token::new(0x04000001);
        let type_token = Token::new(0x02000001);

        storage.set(field, EmValue::I32(42));
        storage.mark_type_initialized(type_token);

        assert!(!storage.is_empty());

        storage.clear();

        assert!(storage.is_empty());
        assert!(!storage.is_type_initialized(type_token));
    }

    #[test]
    fn test_clone() {
        let storage = StaticFieldStorage::new();
        let field = Token::new(0x04000001);
        storage.set(field, EmValue::I32(42));

        let cloned = storage.clone();
        assert_eq!(cloned.get(field), Some(EmValue::I32(42)));

        // Modifications to clone don't affect original
        cloned.set(field, EmValue::I32(100));
        assert_eq!(storage.get(field), Some(EmValue::I32(42)));
        assert_eq!(cloned.get(field), Some(EmValue::I32(100)));
    }

    #[test]
    fn test_fork() {
        let storage = StaticFieldStorage::new();
        let field1 = Token::new(0x04000001);
        let field2 = Token::new(0x04000002);
        let type_token = Token::new(0x02000001);

        // Set up original
        storage.set(field1, EmValue::I32(42));
        storage.mark_type_initialized(type_token);

        // Fork
        let forked = storage.fork();

        // Both see the same data
        assert_eq!(storage.get(field1), Some(EmValue::I32(42)));
        assert_eq!(forked.get(field1), Some(EmValue::I32(42)));
        assert!(storage.is_type_initialized(type_token));
        assert!(forked.is_type_initialized(type_token));

        // Modify forked
        forked.set(field1, EmValue::I32(100));
        forked.set(field2, EmValue::I32(200));

        // Original is unchanged
        assert_eq!(storage.get(field1), Some(EmValue::I32(42)));
        assert!(storage.get(field2).is_none());

        // Forked has new values
        assert_eq!(forked.get(field1), Some(EmValue::I32(100)));
        assert_eq!(forked.get(field2), Some(EmValue::I32(200)));
    }

    #[test]
    fn test_fork_isolation() {
        let storage = StaticFieldStorage::new();
        let field = Token::new(0x04000001);
        storage.set(field, EmValue::I32(1));

        // Create multiple forks
        let fork1 = storage.fork();
        let fork2 = storage.fork();

        // Modify each independently
        fork1.set(field, EmValue::I32(10));
        fork2.set(field, EmValue::I32(20));

        // Each has its own value
        assert_eq!(storage.get(field), Some(EmValue::I32(1)));
        assert_eq!(fork1.get(field), Some(EmValue::I32(10)));
        assert_eq!(fork2.get(field), Some(EmValue::I32(20)));
    }
}
