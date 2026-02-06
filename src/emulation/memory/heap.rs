//! Managed heap implementation for CIL emulation.
//!
//! This module provides [`ManagedHeap`], which simulates the .NET runtime's
//! garbage-collected heap. It supports allocation of:
//!
//! - **Strings** - Immutable .NET strings stored as `Arc<str>`
//! - **Arrays** - Single and multi-dimensional arrays with element type tracking
//! - **Objects** - Class instances with field storage by token
//! - **Boxed values** - Value types wrapped as reference types
//! - **Delegates** - Method references with optional target objects
//! - **Special types** - Encoding and cryptographic algorithm instances for stubs
//!
//! # Interior Mutability
//!
//! The heap uses interior mutability via `RwLock` to allow shared access
//! during emulation. This enables multiple concurrent reads and exclusive
//! writes without requiring `&mut self` on accessor methods.
//!
//! # Copy-on-Write Semantics
//!
//! The heap uses `imbl::HashMap` for O(1) fork operations. When you call `fork()`,
//! both the original and the fork share the same underlying data structure via
//! structural sharing. Only modified entries are copied (true copy-on-write at
//! the data structure level).
//!
//! # Memory Limits
//!
//! The heap enforces a configurable maximum size. Allocation attempts that
//! would exceed this limit return [`EmulationError::HeapMemoryLimitExceeded`](crate::emulation::EmulationError::HeapMemoryLimitExceeded).
//!
//! # Object References
//!
//! Objects are referenced via [`HeapRef`](crate::emulation::HeapRef), an opaque handle
//! that contains an internal ID. References remain valid for the lifetime of the
//! heap (no garbage collection is simulated).

use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

use imbl::HashMap as ImHashMap;

use crate::{
    emulation::{engine::EmulationError, EmValue, HeapRef},
    metadata::{token::Token, typesystem::CilFlavor},
    Result,
};

/// Info about a symmetric algorithm: (algorithm_type, key, iv).
pub type SymmetricAlgorithmInfo = (Arc<str>, Option<Vec<u8>>, Option<Vec<u8>>);

/// Info about a crypto transform: (algorithm, key, iv, is_encryptor).
pub type CryptoTransformInfo = (Arc<str>, Vec<u8>, Vec<u8>, bool);

/// Info about key derivation: (password, salt, iterations, hash_algorithm).
pub type KeyDerivationInfo = (Vec<u8>, Vec<u8>, u32, Arc<str>);

/// Iterator over heap objects.
///
/// This iterator provides lazy access to heap objects. It collects only the
/// object keys upfront (cheap `u64` copies), then looks up and clones each
/// object lazily as iteration proceeds.
///
/// # Efficiency
///
/// More efficient than [`ManagedHeap::to_vec`] when you don't need all objects
/// or want to stop iteration early. Each iteration step acquires a read lock
/// and clones the object.
///
/// # Example
///
/// ```rust,ignore
/// for (heap_ref, object) in heap.iter() {
///     println!("{}: {}", heap_ref, object);
/// }
/// ```
pub struct HeapIter<'a> {
    heap: &'a ManagedHeap,
    keys: std::vec::IntoIter<u64>,
}

impl<'a> Iterator for HeapIter<'a> {
    type Item = (HeapRef, HeapObject);

    fn next(&mut self) -> Option<Self::Item> {
        self.keys.next().and_then(|id| {
            let state = self.heap.state.read().expect("heap lock poisoned");
            state
                .objects
                .get(&id)
                .map(|obj| (HeapRef::new(id), obj.clone()))
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.keys.size_hint()
    }
}

impl<'a> ExactSizeIterator for HeapIter<'a> {}

/// Text encoding type for `System.Text.Encoding` stubs.
///
/// This enum tracks the encoding type for encoding objects allocated on
/// the heap, enabling the emulator to correctly handle string encoding
/// and decoding operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingType {
    /// UTF-8 encoding (variable-width, 1-4 bytes per character).
    Utf8,
    /// ASCII encoding (7-bit, single byte per character).
    Ascii,
    /// UTF-16 Little Endian (Windows Unicode, 2 bytes per character).
    Utf16Le,
    /// UTF-16 Big Endian (2 bytes per character).
    Utf16Be,
    /// UTF-32 encoding (4 bytes per character).
    Utf32,
}

/// Object stored on the managed heap.
///
/// This enum represents all types of objects that can be allocated on the
/// simulated managed heap. Each variant corresponds to a different .NET
/// reference type or special emulator type.
///
/// # Cloning
///
/// Most variants use `Arc` for their string/byte data, making cloning cheap.
/// The [`ManagedHeap`] methods that return objects (like [`get`](ManagedHeap::get))
/// return cloned copies to avoid borrow conflicts.
// ToDo:  Migrate all storage to be Arc rather than having to clone / create expensive copies
#[derive(Clone, Debug)]
pub enum HeapObject {
    /// A .NET string (immutable sequence of UTF-16 chars).
    ///
    /// Stored internally as `Arc<str>` (UTF-8) for efficient, borrow-free access.
    /// Conversion to/from UTF-16 is handled at the API boundary.
    String(Arc<str>),

    /// A single-dimensional array (SZArray).
    ///
    /// Elements are stored as [`EmValue`] instances with the declared element type
    /// tracked separately for type checking.
    Array {
        /// The declared element type.
        element_type: CilFlavor,
        /// The array elements.
        elements: Vec<EmValue>,
    },

    /// A multi-dimensional array.
    ///
    /// Elements are stored in row-major order (C-style) in a flattened vector.
    MultiArray {
        /// The declared element type.
        element_type: CilFlavor,
        /// Dimension lengths (e.g., `[3, 4]` for a 3x4 array).
        dimensions: Vec<usize>,
        /// Flattened elements in row-major order.
        elements: Vec<EmValue>,
    },

    /// A class instance.
    ///
    /// Fields are stored by their metadata token, allowing dynamic field access
    /// without requiring full type resolution.
    Object {
        /// The type token (TypeDef or TypeRef) of the object.
        type_token: Token,
        /// Field values indexed by field token.
        fields: HashMap<Token, EmValue>,
    },

    /// A boxed value type.
    ///
    /// Created by the `box` instruction to convert a value type to a reference type.
    BoxedValue {
        /// The original value type token.
        type_token: Token,
        /// The boxed value.
        value: Box<EmValue>,
    },

    /// A delegate instance.
    ///
    /// Represents a method reference, optionally bound to a target object.
    Delegate {
        /// The delegate type token.
        type_token: Token,
        /// Target object for instance methods, `None` for static methods.
        target: Option<HeapRef>,
        /// The method being referenced.
        method_token: Token,
    },

    /// A `System.Text.Encoding` instance (for encoding stubs).
    Encoding {
        /// The encoding type.
        encoding_type: EncodingType,
    },

    /// A cryptographic hash algorithm instance (for crypto stubs).
    ///
    /// Used to stub `MD5`, `SHA1`, `SHA256`, etc.
    CryptoAlgorithm {
        /// The algorithm name (e.g., "MD5", "SHA1", "SHA256").
        algorithm_type: Arc<str>,
    },

    /// A symmetric encryption algorithm instance (for crypto stubs).
    ///
    /// Used to stub `Aes`, `DES`, `TripleDES`, etc.
    SymmetricAlgorithm {
        /// The algorithm name (e.g., "AES", "DES", "TripleDES").
        algorithm_type: Arc<str>,
        /// The encryption key, if set.
        key: Option<Vec<u8>>,
        /// The initialization vector, if set.
        iv: Option<Vec<u8>>,
    },

    /// A crypto transform instance (encryptor/decryptor).
    ///
    /// Represents an `ICryptoTransform` implementation with all parameters
    /// needed to perform actual encryption/decryption.
    CryptoTransform {
        /// The algorithm name (e.g., "AES", "DES", "TripleDES", "Rijndael").
        algorithm: Arc<str>,
        /// The encryption key.
        key: Vec<u8>,
        /// The initialization vector.
        iv: Vec<u8>,
        /// Whether this is an encryptor (true) or decryptor (false).
        is_encryptor: bool,
    },

    /// A reflection method info object.
    ///
    /// Created by `Module.ResolveMethod()` to track the resolved method token.
    /// Used by `MethodBase.Invoke()` to determine which method to call.
    ReflectionMethod {
        /// The method token that was resolved.
        method_token: Token,
    },

    /// A key derivation function instance (PBKDF2, PasswordDeriveBytes).
    ///
    /// Stores the parameters needed to derive cryptographic keys from passwords.
    /// Used by `Rfc2898DeriveBytes` and `PasswordDeriveBytes` stubs.
    KeyDerivation {
        /// The password bytes (UTF-8 encoded).
        password: Vec<u8>,
        /// The salt bytes.
        salt: Vec<u8>,
        /// The iteration count for PBKDF2.
        iterations: u32,
        /// The hash algorithm ("SHA1", "SHA256", "SHA384", "SHA512").
        hash_algorithm: Arc<str>,
    },

    /// A stream instance (MemoryStream, resource stream, etc.).
    ///
    /// Stores the stream data buffer and current read/write position.
    /// Used by `GetManifestResourceStream`, `MemoryStream`, etc.
    Stream {
        /// The stream data buffer (mutable for write support).
        data: Vec<u8>,
        /// Current position in the stream.
        position: usize,
    },

    /// A CryptoStream instance wrapping another stream with encryption/decryption.
    ///
    /// Uses "transform-all-at-once" approach: on first read/flush, the entire
    /// underlying data is transformed and cached. This is simpler than true
    /// streaming but sufficient for deobfuscation purposes.
    CryptoStream {
        /// The underlying stream to read from or write to.
        underlying_stream: HeapRef,
        /// The crypto transform (encryptor/decryptor).
        transform: HeapRef,
        /// The mode: 0 = Read (decrypt from underlying), 1 = Write (encrypt to underlying).
        mode: u8,
        /// Cached transformed data (decrypted for Read mode, encrypted for Write mode).
        /// `None` until the first read or flush triggers transformation.
        transformed_data: Option<Vec<u8>>,
        /// Current read position in the transformed data.
        transformed_pos: usize,
        /// Write buffer accumulating data before transformation (Write mode only).
        write_buffer: Vec<u8>,
    },
}

impl HeapObject {
    /// Returns a human-readable description of the object kind.
    ///
    /// This is useful for error messages and debugging output.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            HeapObject::String(_) => "string",
            HeapObject::Array { .. } => "array",
            HeapObject::MultiArray { .. } => "multi-dimensional array",
            HeapObject::Object { .. } => "object",
            HeapObject::BoxedValue { .. } => "boxed value",
            HeapObject::Delegate { .. } => "delegate",
            HeapObject::Encoding { .. } => "encoding",
            HeapObject::CryptoAlgorithm { .. } => "crypto algorithm",
            HeapObject::SymmetricAlgorithm { .. } => "symmetric algorithm",
            HeapObject::CryptoTransform { .. } => "crypto transform",
            HeapObject::ReflectionMethod { .. } => "reflection method",
            HeapObject::KeyDerivation { .. } => "key derivation",
            HeapObject::Stream { .. } => "stream",
            HeapObject::CryptoStream { .. } => "crypto stream",
        }
    }

    /// Returns the estimated size of this object in bytes.
    ///
    /// This is used for heap memory limit tracking. The estimate includes
    /// object header overhead and data storage, but is not exact.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        match self {
            HeapObject::String(s) => 24 + s.len() * 2, // Object header + UTF-16
            HeapObject::Array { elements, .. } => 24 + elements.len() * 8,
            HeapObject::MultiArray { elements, .. } => 32 + elements.len() * 8,
            HeapObject::Object { fields, .. } => 24 + fields.len() * 16,
            HeapObject::BoxedValue { .. }
            | HeapObject::CryptoAlgorithm { .. }
            | HeapObject::ReflectionMethod { .. } => 32,
            HeapObject::CryptoTransform { key, iv, .. } => 48 + key.len() + iv.len(),
            HeapObject::Delegate { .. } => 48,
            HeapObject::Encoding { .. } => 24,
            HeapObject::SymmetricAlgorithm { key, iv, .. } => {
                32 + key.as_ref().map_or(0, Vec::len) + iv.as_ref().map_or(0, Vec::len)
            }
            HeapObject::KeyDerivation { password, salt, .. } => 48 + password.len() + salt.len(),
            HeapObject::Stream { data, .. } => 32 + data.len(),
            HeapObject::CryptoStream {
                transformed_data,
                write_buffer,
                ..
            } => 64 + transformed_data.as_ref().map_or(0, Vec::len) + write_buffer.len(),
        }
    }
}

impl fmt::Display for HeapObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeapObject::String(s) => {
                if s.len() > 50 {
                    write!(f, "\"{}...\"", &s[..47])
                } else {
                    write!(f, "\"{s}\"")
                }
            }
            HeapObject::Array {
                element_type,
                elements,
            } => {
                write!(f, "{:?}[{}]", element_type, elements.len())
            }
            HeapObject::MultiArray {
                element_type,
                dimensions,
                ..
            } => {
                write!(f, "{:?}[", element_type)?;
                for (i, dim) in dimensions.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{dim}")?;
                }
                write!(f, "]")
            }
            HeapObject::Object { type_token, .. } => {
                write!(f, "object({type_token})")
            }
            HeapObject::BoxedValue { type_token, value } => {
                write!(f, "boxed({type_token}, {value})")
            }
            HeapObject::Delegate {
                type_token,
                method_token,
                ..
            } => {
                write!(f, "delegate({type_token}, {method_token})")
            }
            HeapObject::Encoding { encoding_type } => {
                write!(f, "encoding({encoding_type:?})")
            }
            HeapObject::CryptoAlgorithm { algorithm_type } => {
                write!(f, "crypto_algorithm({algorithm_type})")
            }
            HeapObject::SymmetricAlgorithm { algorithm_type, .. } => {
                write!(f, "symmetric_algorithm({algorithm_type})")
            }
            HeapObject::CryptoTransform {
                algorithm,
                is_encryptor,
                key,
                ..
            } => {
                let mode = if *is_encryptor { "encrypt" } else { "decrypt" };
                write!(
                    f,
                    "crypto_transform({} {} key={}B)",
                    algorithm,
                    mode,
                    key.len()
                )
            }
            HeapObject::ReflectionMethod { method_token } => {
                write!(f, "reflection_method(0x{:08x})", method_token.value())
            }
            HeapObject::KeyDerivation {
                hash_algorithm,
                iterations,
                ..
            } => {
                write!(
                    f,
                    "key_derivation({hash_algorithm}, {iterations} iterations)"
                )
            }
            HeapObject::Stream { data, position } => {
                write!(f, "stream({} bytes, pos={})", data.len(), position)
            }
            HeapObject::CryptoStream {
                mode,
                transformed_data,
                write_buffer,
                ..
            } => {
                let mode_str = if *mode == 0 { "Read" } else { "Write" };
                let cached = transformed_data.as_ref().map_or(0, Vec::len);
                let buffered = write_buffer.len();
                write!(
                    f,
                    "crypto_stream(mode={}, cached={}, buffered={})",
                    mode_str, cached, buffered
                )
            }
        }
    }
}

/// Internal state of the managed heap, protected by `RwLock`.
///
/// This struct holds the mutable state that is shared across all heap
/// operations. It is wrapped in `RwLock` to enable concurrent reads
/// and exclusive writes.
///
/// Uses `imbl::HashMap` for O(1) fork via structural sharing.
#[derive(Clone, Debug)]
struct HeapState {
    /// Object storage indexed by reference ID.
    ///
    /// Uses `imbl::HashMap` for O(1) cloning via structural sharing.
    /// This enables efficient `fork()` operations where parent and child
    /// share unmodified entries.
    objects: ImHashMap<u64, HeapObject>,
}

/// Simulated managed heap for CIL emulation.
///
/// The managed heap allocates and tracks objects, arrays, and strings.
/// It enforces memory limits to prevent runaway allocation.
///
/// # Interior Mutability
///
/// This struct uses interior mutability via `RwLock`, allowing methods to
/// take `&self` instead of `&mut self`. This enables concurrent access patterns
/// and avoids borrow checker conflicts when accessing multiple heap objects.
///
/// # Copy-on-Write Semantics
///
/// The heap uses `imbl::HashMap` internally, which provides O(1) `clone()`
/// through structural sharing. The `fork()` method creates an independent
/// copy of the heap that shares unmodified data with the original.
///
/// # Memory Limits
///
/// The heap has a configurable maximum size. Exceeding this limit returns
/// an error.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::ManagedHeap;
///
/// let heap = ManagedHeap::new(1024 * 1024); // 1MB limit
///
/// // Allocate a string
/// let string_ref = heap.alloc_string("Hello, World!").unwrap();
///
/// // Read the string (returns Arc<str> for borrow-free access)
/// let value = heap.get_string(string_ref).unwrap();
/// assert_eq!(&*value, "Hello, World!");
///
/// // Fork creates an independent copy (O(1) operation!)
/// let forked = heap.fork();
/// // Both heaps share unmodified data via structural sharing
/// ```
#[derive(Debug)]
pub struct ManagedHeap {
    /// Internal state protected by RwLock.
    /// Contains the imbl::HashMap for O(1) fork.
    state: RwLock<HeapState>,
    /// Next reference ID to allocate (atomic for lock-free allocation IDs).
    next_id: AtomicU64,
    /// Current estimated heap size in bytes (atomic for lock-free reads).
    current_size: AtomicUsize,
    /// Maximum allowed heap size in bytes.
    max_size: usize,
}

impl ManagedHeap {
    /// Creates a new managed heap with the given size limit.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum heap size in bytes
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        ManagedHeap {
            state: RwLock::new(HeapState {
                objects: ImHashMap::new(),
            }),
            next_id: AtomicU64::new(1),
            current_size: AtomicUsize::new(0),
            max_size,
        }
    }

    /// Creates a managed heap with default size (64MB).
    #[must_use]
    pub fn default_size() -> Self {
        Self::new(64 * 1024 * 1024)
    }

    /// Checks if allocation would exceed memory limit.
    ///
    /// Returns `Ok(())` if the allocation can proceed, or an error if the
    /// allocation would exceed [`max_size`](Self::max_size).
    fn check_allocation(&self, size: usize) -> Result<()> {
        let current = self.current_size.load(Ordering::Relaxed);
        if current + size > self.max_size {
            return Err(EmulationError::HeapMemoryLimitExceeded {
                current,
                limit: self.max_size,
            }
            .into());
        }
        Ok(())
    }

    /// Internal helper to allocate an object on the heap.
    ///
    /// This consolidates the common allocation pattern: check size limits,
    /// generate ID, insert object, update size tracking.
    fn alloc_object_internal(&self, obj: HeapObject) -> Result<HeapRef> {
        let size = obj.estimated_size();
        self.check_allocation(size)?;

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let heap_ref = HeapRef::new(id);

        let mut state = self.state.write().expect("heap lock poisoned");
        state.objects.insert(heap_ref.id(), obj);
        self.current_size.fetch_add(size, Ordering::Relaxed);

        Ok(heap_ref)
    }

    /// Forks this heap, creating an independent copy with CoW semantics.
    ///
    /// The forked heap shares its data structure with the original via
    /// structural sharing. Both heaps can be modified independently -
    /// only the modified entries are copied (true copy-on-write).
    ///
    /// # Performance
    ///
    /// This is an O(1) operation due to `imbl::HashMap`'s structural sharing.
    /// The actual data is only copied when either heap modifies an entry.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let heap = ManagedHeap::new(1024 * 1024);
    /// let string_ref = heap.alloc_string("Hello").unwrap();
    ///
    /// let forked = heap.fork();
    ///
    /// // Both heaps see the same string
    /// assert_eq!(heap.get_string(string_ref).unwrap().as_ref(), "Hello");
    /// assert_eq!(forked.get_string(string_ref).unwrap().as_ref(), "Hello");
    ///
    /// // Modifications to forked don't affect original
    /// let new_ref = forked.alloc_string("World").unwrap();
    /// assert!(forked.contains(new_ref));
    /// assert!(!heap.contains(new_ref));
    /// ```
    #[must_use]
    pub fn fork(&self) -> Self {
        let state = self.state.read().expect("heap lock poisoned");
        ManagedHeap {
            // imbl::HashMap::clone() is O(1) - structural sharing!
            state: RwLock::new(HeapState {
                objects: state.objects.clone(),
            }),
            next_id: AtomicU64::new(self.next_id.load(Ordering::SeqCst)),
            current_size: AtomicUsize::new(self.current_size.load(Ordering::Relaxed)),
            max_size: self.max_size,
        }
    }

    /// Allocates a string on the heap.
    ///
    /// # Arguments
    ///
    /// * `value` - The string value
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_string(&self, value: &str) -> Result<HeapRef> {
        let arc_str: Arc<str> = value.into();
        self.alloc_object_internal(HeapObject::String(arc_str))
    }

    /// Allocates a single-dimensional array on the heap.
    ///
    /// # Arguments
    ///
    /// * `element_type` - Type of array elements
    /// * `length` - Number of elements
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_array(&self, element_type: CilFlavor, length: usize) -> Result<HeapRef> {
        let elements = vec![EmValue::default_for_flavor(&element_type); length];
        self.alloc_object_internal(HeapObject::Array {
            element_type,
            elements,
        })
    }

    /// Allocates an array with explicit initial values.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_array_with_values(
        &self,
        element_type: CilFlavor,
        elements: Vec<EmValue>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::Array {
            element_type,
            elements,
        })
    }

    /// Allocates a multi-dimensional array on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_multi_array(
        &self,
        element_type: CilFlavor,
        dimensions: Vec<usize>,
    ) -> Result<HeapRef> {
        let total_elements: usize = dimensions.iter().product();
        let elements = vec![EmValue::default_for_flavor(&element_type); total_elements];
        self.alloc_object_internal(HeapObject::MultiArray {
            element_type,
            dimensions,
            elements,
        })
    }

    /// Allocates an object instance on the heap.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token of the object
    /// * `field_types` - Field tokens and their types for initialization
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_object_with_fields(
        &self,
        type_token: Token,
        field_types: &[(Token, CilFlavor)],
    ) -> Result<HeapRef> {
        let mut fields = HashMap::new();
        for (token, cil_flavor) in field_types {
            fields.insert(*token, EmValue::default_for_flavor(cil_flavor));
        }
        self.alloc_object_internal(HeapObject::Object { type_token, fields })
    }

    /// Allocates an empty object instance on the heap.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token of the object
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_object(&self, type_token: Token) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::Object {
            type_token,
            fields: HashMap::new(),
        })
    }

    /// Allocates a boxed value on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_boxed(&self, type_token: Token, value: EmValue) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::BoxedValue {
            type_token,
            value: Box::new(value),
        })
    }

    /// Allocates a delegate on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_delegate(
        &self,
        type_token: Token,
        target: Option<HeapRef>,
        method_token: Token,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::Delegate {
            type_token,
            target,
            method_token,
        })
    }

    /// Gets a clone of an object from the heap.
    ///
    /// Returns a cloned `HeapObject` to avoid borrow conflicts. For strings
    /// and other Arc-backed data, cloning is cheap (just incrementing a
    /// reference count).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::InvalidHeapReference`] if the reference is invalid.
    pub fn get(&self, heap_ref: HeapRef) -> Result<HeapObject> {
        let state = self.state.read().expect("heap lock poisoned");
        state.objects.get(&heap_ref.id()).cloned().ok_or(
            EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into(),
        )
    }

    /// Applies a mutation function to an object on the heap.
    ///
    /// This method provides controlled mutable access while maintaining
    /// interior mutability semantics.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::InvalidHeapReference`] if the reference is invalid.
    pub fn with_object_mut<F, R>(&self, heap_ref: HeapRef, f: F) -> Result<R>
    where
        F: FnOnce(&mut HeapObject) -> Result<R>,
    {
        let mut state = self.state.write().expect("heap lock poisoned");
        let obj =
            state
                .objects
                .get_mut(&heap_ref.id())
                .ok_or(EmulationError::InvalidHeapReference {
                    reference_id: heap_ref.id(),
                })?;
        f(obj)
    }

    /// Gets a string from the heap.
    ///
    /// Returns an `Arc<str>` for efficient, borrow-free access. This allows
    /// holding onto the string while performing other heap operations.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or doesn't point to a string.
    pub fn get_string(&self, heap_ref: HeapRef) -> Result<Arc<str>> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::String(s)) => Ok(Arc::clone(s)),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "string",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets an array element (cloned).
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid, not an array, or index out of bounds.
    pub fn get_array_element(&self, heap_ref: HeapRef, index: usize) -> Result<EmValue> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Array { elements, .. }) => {
                if index >= elements.len() {
                    Err(EmulationError::ArrayIndexOutOfBounds {
                        index: i64::try_from(index).unwrap_or(i64::MAX),
                        length: elements.len(),
                    }
                    .into())
                } else {
                    Ok(elements[index].clone())
                }
            }
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "array",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Sets an array element.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid, not an array, or index out of bounds.
    pub fn set_array_element(&self, heap_ref: HeapRef, index: usize, value: EmValue) -> Result<()> {
        let mut state = self.state.write().expect("heap lock poisoned");
        match state.objects.get_mut(&heap_ref.id()) {
            Some(HeapObject::Array { elements, .. }) => {
                if index >= elements.len() {
                    Err(EmulationError::ArrayIndexOutOfBounds {
                        index: i64::try_from(index).unwrap_or(i64::MAX),
                        length: elements.len(),
                    }
                    .into())
                } else {
                    elements[index] = value;
                    Ok(())
                }
            }
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "array",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets the length of an array.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not an array.
    pub fn get_array_length(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Array { elements, .. }) => Ok(elements.len()),
            Some(HeapObject::MultiArray { dimensions, .. }) => Ok(dimensions.iter().product()),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "array",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets the element type of an array.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not an array.
    pub fn get_array_element_type(&self, heap_ref: HeapRef) -> Result<CilFlavor> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Array { element_type, .. }) => Ok(element_type.clone()),
            Some(HeapObject::MultiArray { element_type, .. }) => Ok(element_type.clone()),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "array",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets an object field value (cloned).
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid, not an object, or field not found.
    pub fn get_field(&self, heap_ref: HeapRef, field_token: Token) -> Result<EmValue> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Object { fields, .. }) => fields
                .get(&field_token)
                .cloned()
                .ok_or(EmulationError::FieldNotFound { token: field_token }.into()),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "object",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Sets an object field value.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not an object.
    pub fn set_field(&self, heap_ref: HeapRef, field_token: Token, value: EmValue) -> Result<()> {
        let mut state = self.state.write().expect("heap lock poisoned");
        match state.objects.get_mut(&heap_ref.id()) {
            Some(HeapObject::Object { fields, .. }) => {
                fields.insert(field_token, value);
                Ok(())
            }
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "object",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets the type token of an object.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid.
    pub fn get_type_token(&self, heap_ref: HeapRef) -> Result<Token> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id()) {
            Some(
                HeapObject::Object { type_token, .. }
                | HeapObject::BoxedValue { type_token, .. }
                | HeapObject::Delegate { type_token, .. },
            ) => Ok(*type_token),
            // String and array have well-known types
            Some(HeapObject::String(_)) => Ok(Token::new(0x0100_0001)), // Placeholder
            Some(HeapObject::Array { .. } | HeapObject::MultiArray { .. }) => {
                Ok(Token::new(0x0100_0002))
            }
            Some(HeapObject::Encoding { .. }) => Ok(Token::new(0x0100_0003)), // Placeholder for Encoding
            // Crypto-related objects use placeholder tokens
            Some(HeapObject::CryptoAlgorithm { .. }) => Ok(Token::new(0x0100_0004)),
            Some(HeapObject::SymmetricAlgorithm { .. }) => Ok(Token::new(0x0100_0005)),
            Some(HeapObject::CryptoTransform { .. }) => Ok(Token::new(0x0100_0006)),
            // Reflection method uses the stored method token as its type (for identification)
            Some(HeapObject::ReflectionMethod { method_token }) => Ok(*method_token),
            // Key derivation uses a placeholder token
            Some(HeapObject::KeyDerivation { .. }) => Ok(Token::new(0x0100_0007)),
            // Stream uses a placeholder token
            Some(HeapObject::Stream { .. }) => Ok(Token::new(0x0100_0008)),
            // CryptoStream uses a placeholder token
            Some(HeapObject::CryptoStream { .. }) => Ok(Token::new(0x0100_0009)),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Unboxes a value from the heap (cloned).
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not a boxed value.
    pub fn unbox(&self, heap_ref: HeapRef) -> Result<EmValue> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::BoxedValue { value, .. }) => Ok((**value).clone()),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "boxed value",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets the boxed value (cloned) from the heap.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not a boxed value.
    pub fn get_boxed_value(&self, heap_ref: HeapRef) -> Result<EmValue> {
        self.unbox(heap_ref)
    }

    /// Returns `true` if the reference exists on the heap.
    #[must_use]
    pub fn contains(&self, heap_ref: HeapRef) -> bool {
        let state = self.state.read().expect("heap lock poisoned");
        state.objects.contains_key(&heap_ref.id())
    }

    /// Returns the current estimated heap size in bytes.
    #[must_use]
    pub fn current_size(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }

    /// Returns the maximum heap size in bytes.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Returns the number of allocated objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        let state = self.state.read().expect("heap lock poisoned");
        state.objects.len()
    }

    /// Clears all objects from the heap.
    ///
    /// Note: This doesn't simulate GC, it just empties the heap.
    pub fn clear(&self) {
        let mut state = self.state.write().expect("heap lock poisoned");
        state.objects.clear();
        self.current_size.store(0, Ordering::Relaxed);
    }

    /// Returns all heap objects as a vector of (HeapRef, HeapObject) pairs.
    ///
    /// This clones all objects, which may be expensive for large heaps.
    #[must_use]
    pub fn to_vec(&self) -> Vec<(HeapRef, HeapObject)> {
        let state = self.state.read().expect("heap lock poisoned");
        state
            .objects
            .iter()
            .map(|(&id, obj)| (HeapRef::new(id), obj.clone()))
            .collect()
    }

    /// Returns a lazy iterator over all heap objects.
    ///
    /// Only collects object keys upfront (cheap u64 copies), then clones
    /// each object lazily as you iterate. More efficient than `to_vec()`
    /// if you don't need all objects or want to stop iteration early.
    pub fn iter(&self) -> HeapIter<'_> {
        let keys: Vec<u64> = {
            let state = self.state.read().expect("heap lock poisoned");
            state.objects.keys().copied().collect()
        };
        HeapIter {
            heap: self,
            keys: keys.into_iter(),
        }
    }

    /// Returns the number of modified entries since fork (for diagnostics).
    ///
    /// Note: This is an approximation based on imbl's internal structure.
    /// After fork, unmodified entries are shared, so this helps understand
    /// memory usage.
    #[must_use]
    pub fn object_count_estimate(&self) -> usize {
        let state = self.state.read().expect("heap lock poisoned");
        state.objects.len()
    }

    /// Allocates a byte array on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_byte_array(&self, data: &[u8]) -> Result<HeapRef> {
        let elements: Vec<EmValue> = data.iter().map(|&b| EmValue::I32(i32::from(b))).collect();
        self.alloc_array_with_values(CilFlavor::U1, elements)
    }

    /// Gets a byte array from the heap.
    ///
    /// Returns `None` if the reference is invalid, not a byte array, or contains
    /// any non-I32 elements (including Symbolic values). This fail-fast behavior
    /// ensures callers don't silently receive partial/corrupted data.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn get_byte_array(&self, heap_ref: HeapRef) -> Option<Vec<u8>> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::Array { elements, .. } => {
                let mut bytes = Vec::with_capacity(elements.len());
                for e in elements.iter() {
                    match e {
                        EmValue::I32(n) => bytes.push(*n as u8),
                        _ => return None, // Fail if any element is not I32
                    }
                }
                Some(bytes)
            }
            _ => None,
        }
    }

    /// Converts an array's elements to a byte vector, respecting element type.
    ///
    /// Unlike `get_byte_array` which only takes the low byte, this method
    /// properly serializes multi-byte elements (uint32, int64, etc.) to bytes
    /// in little-endian order.
    ///
    /// Returns `None` if the reference is invalid, not an array, or contains
    /// non-numeric types.
    #[must_use]
    pub fn get_array_as_bytes(&self, heap_ref: HeapRef) -> Option<Vec<u8>> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::Array {
                elements,
                element_type,
            } => {
                let element_size = element_type.element_size().unwrap_or(1);
                let mut bytes = Vec::with_capacity(elements.len() * element_size);

                for e in elements.iter() {
                    match e {
                        EmValue::I32(n) => match element_size {
                            1 => bytes.push(*n as u8),
                            2 => bytes.extend_from_slice(&(*n as i16).to_le_bytes()),
                            4 => bytes.extend_from_slice(&n.to_le_bytes()),
                            _ => bytes.push(*n as u8),
                        },
                        EmValue::I64(n) => {
                            bytes.extend_from_slice(&n.to_le_bytes());
                        }
                        EmValue::F32(f) => {
                            bytes.extend_from_slice(&f.to_le_bytes());
                        }
                        EmValue::F64(f) => {
                            bytes.extend_from_slice(&f.to_le_bytes());
                        }
                        _ => return None, // Non-numeric type
                    }
                }
                Some(bytes)
            }
            _ => None,
        }
    }

    /// Gets a string from the heap (convenience returning Option).
    #[must_use]
    pub fn get_string_opt(&self, heap_ref: HeapRef) -> Option<Arc<str>> {
        self.get_string(heap_ref).ok()
    }

    /// Allocates an encoding object on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_encoding(&self, encoding_type: EncodingType) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::Encoding { encoding_type })
    }

    /// Gets the encoding type from an encoding object.
    #[must_use]
    pub fn get_encoding_type(&self, heap_ref: HeapRef) -> Option<EncodingType> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::Encoding { encoding_type } => Some(*encoding_type),
            _ => None,
        }
    }

    /// Allocates a cryptographic hash algorithm object.
    ///
    /// Used for MD5, SHA1, SHA256, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_crypto_algorithm(&self, algorithm_type: &str) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::CryptoAlgorithm {
            algorithm_type: algorithm_type.into(),
        })
    }

    /// Gets the algorithm type from a crypto algorithm object.
    ///
    /// Returns an `Arc<str>` for efficient, borrow-free access.
    #[must_use]
    pub fn get_crypto_algorithm_type(&self, heap_ref: HeapRef) -> Option<Arc<str>> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::CryptoAlgorithm { algorithm_type } => Some(Arc::clone(algorithm_type)),
            _ => None,
        }
    }

    /// Allocates a symmetric encryption algorithm object.
    ///
    /// Used for AES, DES, TripleDES, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_symmetric_algorithm(&self, algorithm_type: &str) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::SymmetricAlgorithm {
            algorithm_type: algorithm_type.into(),
            key: None,
            iv: None,
        })
    }

    /// Sets the key for a symmetric algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap reference is invalid or not a symmetric algorithm.
    pub fn set_symmetric_key(&self, heap_ref: HeapRef, key: Vec<u8>) -> Result<()> {
        let mut state = self.state.write().expect("heap lock poisoned");
        if let Some(HeapObject::SymmetricAlgorithm { key: key_slot, .. }) =
            state.objects.get_mut(&heap_ref.id())
        {
            *key_slot = Some(key);
            return Ok(());
        }
        Err(EmulationError::HeapTypeMismatch {
            expected: "SymmetricAlgorithm",
            found: "other",
        }
        .into())
    }

    /// Sets the IV for a symmetric algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap reference is invalid or not a symmetric algorithm.
    pub fn set_symmetric_iv(&self, heap_ref: HeapRef, iv: Vec<u8>) -> Result<()> {
        let mut state = self.state.write().expect("heap lock poisoned");
        if let Some(HeapObject::SymmetricAlgorithm { iv: iv_slot, .. }) =
            state.objects.get_mut(&heap_ref.id())
        {
            *iv_slot = Some(iv);
            return Ok(());
        }
        Err(EmulationError::HeapTypeMismatch {
            expected: "SymmetricAlgorithm",
            found: "other",
        }
        .into())
    }

    /// Gets the symmetric algorithm parameters.
    ///
    /// # Returns
    ///
    /// A tuple of (algorithm_type, key, iv) if valid, or `None` otherwise.
    #[must_use]
    pub fn get_symmetric_algorithm_info(
        &self,
        heap_ref: HeapRef,
    ) -> Option<SymmetricAlgorithmInfo> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::SymmetricAlgorithm {
                algorithm_type,
                key,
                iv,
            } => Some((algorithm_type.clone(), key.clone(), iv.clone())),
            _ => None,
        }
    }

    /// Allocates a crypto transform object (encryptor/decryptor).
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    /// Allocates a crypto transform with all parameters needed for encryption/decryption.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm name (e.g., "AES", "DES", "Rijndael")
    /// * `key` - The encryption/decryption key
    /// * `iv` - The initialization vector
    /// * `is_encryptor` - True for encryption, false for decryption
    pub fn alloc_crypto_transform(
        &self,
        algorithm: &str,
        key: Vec<u8>,
        iv: Vec<u8>,
        is_encryptor: bool,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::CryptoTransform {
            algorithm: algorithm.into(),
            key,
            iv,
            is_encryptor,
        })
    }

    /// Gets the crypto transform parameters.
    ///
    /// # Returns
    ///
    /// A tuple of (algorithm, key, iv, is_encryptor) if valid, or `None` otherwise.
    #[must_use]
    pub fn get_crypto_transform_info(&self, heap_ref: HeapRef) -> Option<CryptoTransformInfo> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::CryptoTransform {
                algorithm,
                key,
                iv,
                is_encryptor,
            } => Some((algorithm.clone(), key.clone(), iv.clone(), *is_encryptor)),
            _ => None,
        }
    }

    /// Allocates a reflection method info object on the heap.
    ///
    /// Creates a `ReflectionMethod` object that stores the resolved method token.
    /// Used by reflection stubs to track method resolution for later invocation.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the resolved method.
    ///
    /// # Returns
    ///
    /// A [`HeapRef`] pointing to the new reflection method object.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_reflection_method(&self, method_token: Token) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::ReflectionMethod { method_token })
    }

    /// Gets the method token from a reflection method object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the reflection method object.
    ///
    /// # Returns
    ///
    /// The method token if the reference points to a `ReflectionMethod`, or `None` otherwise.
    #[must_use]
    pub fn get_reflection_method_token(&self, heap_ref: HeapRef) -> Option<Token> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::ReflectionMethod { method_token } => Some(*method_token),
            _ => None,
        }
    }

    /// Replaces a heap object with a key derivation object.
    ///
    /// This is used by constructor stubs to replace the pre-allocated generic object
    /// with a specialized `KeyDerivation` object storing PBKDF2 parameters.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object to replace.
    /// * `password` - The password bytes.
    /// * `salt` - The salt bytes.
    /// * `iterations` - The iteration count.
    /// * `hash_algorithm` - The hash algorithm name (e.g., "SHA1", "SHA256").
    ///
    /// # Errors
    ///
    /// Returns an error if the heap reference is invalid.
    pub fn replace_with_key_derivation(
        &self,
        heap_ref: HeapRef,
        password: Vec<u8>,
        salt: Vec<u8>,
        iterations: u32,
        hash_algorithm: &str,
    ) -> Result<()> {
        let mut state = self.state.write().expect("heap lock poisoned");
        if state.objects.contains_key(&heap_ref.id()) {
            state.objects.insert(
                heap_ref.id(),
                HeapObject::KeyDerivation {
                    password,
                    salt,
                    iterations,
                    hash_algorithm: hash_algorithm.into(),
                },
            );
            Ok(())
        } else {
            Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into())
        }
    }

    /// Allocates a key derivation object on the heap.
    ///
    /// Creates a `KeyDerivation` object that stores PBKDF2 parameters.
    /// Used by `Rfc2898DeriveBytes` and `PasswordDeriveBytes` stubs.
    ///
    /// # Arguments
    ///
    /// * `password` - The password bytes.
    /// * `salt` - The salt bytes.
    /// * `iterations` - The iteration count.
    /// * `hash_algorithm` - The hash algorithm name (e.g., "SHA1", "SHA256").
    ///
    /// # Returns
    ///
    /// A [`HeapRef`] pointing to the new key derivation object.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_key_derivation(
        &self,
        password: Vec<u8>,
        salt: Vec<u8>,
        iterations: u32,
        hash_algorithm: &str,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::KeyDerivation {
            password,
            salt,
            iterations,
            hash_algorithm: hash_algorithm.into(),
        })
    }

    /// Gets the key derivation parameters from a key derivation object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the key derivation object.
    ///
    /// # Returns
    ///
    /// A tuple of (password, salt, iterations, hash_algorithm) if the reference
    /// points to a `KeyDerivation`, or `None` otherwise.
    #[must_use]
    pub fn get_key_derivation_params(&self, heap_ref: HeapRef) -> Option<KeyDerivationInfo> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::KeyDerivation {
                password,
                salt,
                iterations,
                hash_algorithm,
            } => Some((
                password.clone(),
                salt.clone(),
                *iterations,
                hash_algorithm.clone(),
            )),
            _ => None,
        }
    }

    /// Allocates a new stream object with the given data.
    ///
    /// Creates a `Stream` heap object initialized with the provided data buffer
    /// and position set to 0. This is used for `MemoryStream` and resource streams.
    ///
    /// # Arguments
    ///
    /// * `data` - The stream data buffer.
    ///
    /// # Returns
    ///
    /// A [`HeapRef`] pointing to the new stream object.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_stream(&self, data: Vec<u8>) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::Stream { data, position: 0 })
    }

    /// Gets the stream data and position from a stream object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the stream object.
    ///
    /// # Returns
    ///
    /// A tuple of (data clone, position) if the reference points to a `Stream`,
    /// or `None` otherwise.
    #[must_use]
    pub fn get_stream_data(&self, heap_ref: HeapRef) -> Option<(Vec<u8>, usize)> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::Stream { data, position } => Some((data.clone(), *position)),
            _ => None,
        }
    }

    /// Updates the position of a stream object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the stream object.
    /// * `new_position` - The new position to set.
    ///
    /// # Returns
    ///
    /// `true` if the stream was updated, `false` if the reference doesn't point
    /// to a stream object.
    pub fn set_stream_position(&self, heap_ref: HeapRef, new_position: usize) -> bool {
        let mut state = self.state.write().expect("heap lock poisoned");
        if let Some(HeapObject::Stream { position, .. }) = state.objects.get_mut(&heap_ref.id()) {
            *position = new_position;
            true
        } else {
            false
        }
    }

    /// Writes data to a stream at the current position.
    ///
    /// If the position is at the end of the stream, data is appended.
    /// If the position is in the middle, data overwrites existing bytes
    /// and extends the stream if necessary.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the stream object.
    /// * `bytes` - The bytes to write.
    ///
    /// # Returns
    ///
    /// The number of bytes written, or 0 if the reference is not a stream.
    pub fn write_to_stream(&self, heap_ref: HeapRef, bytes: &[u8]) -> usize {
        let mut state = self.state.write().expect("heap lock poisoned");
        if let Some(HeapObject::Stream { data, position }) = state.objects.get_mut(&heap_ref.id()) {
            let write_len = bytes.len();

            // Ensure capacity
            let required_len = *position + write_len;
            if data.len() < required_len {
                data.resize(required_len, 0);
            }

            // Copy bytes to the stream
            data[*position..*position + write_len].copy_from_slice(bytes);

            // Advance position
            *position += write_len;

            // Update size estimate
            // (We don't track size changes precisely here, but that's acceptable)

            write_len
        } else {
            0
        }
    }

    /// Replaces an existing heap object with a stream object.
    ///
    /// This is used by stream constructors to convert a generic object (allocated
    /// by `newobj`) into a proper Stream with data. The original object is replaced
    /// in place, preserving the HeapRef.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object to replace.
    /// * `data` - The stream data buffer.
    ///
    /// # Returns
    ///
    /// `true` if the object was replaced, `false` if the reference is invalid.
    pub fn replace_with_stream(&self, heap_ref: HeapRef, data: Vec<u8>) -> bool {
        let mut state = self.state.write().expect("heap lock poisoned");
        if let Some(old_obj) = state.objects.get(&heap_ref.id()) {
            let old_size = old_obj.estimated_size();
            let new_obj = HeapObject::Stream { data, position: 0 };
            let new_size = new_obj.estimated_size();
            state.objects.insert(heap_ref.id(), new_obj);

            // Update size tracking atomically
            if new_size >= old_size {
                self.current_size
                    .fetch_add(new_size - old_size, Ordering::Relaxed);
            } else {
                self.current_size
                    .fetch_sub(old_size - new_size, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    /// Allocates a new CryptoStream object.
    ///
    /// # Arguments
    ///
    /// * `underlying_stream` - Reference to the underlying stream.
    /// * `transform` - Reference to the crypto transform.
    /// * `mode` - 0 for Read mode, 1 for Write mode.
    ///
    /// # Returns
    ///
    /// A [`HeapRef`] pointing to the new CryptoStream object.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_crypto_stream(
        &self,
        underlying_stream: HeapRef,
        transform: HeapRef,
        mode: u8,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::CryptoStream {
            underlying_stream,
            transform,
            mode,
            transformed_data: None,
            transformed_pos: 0,
            write_buffer: Vec::new(),
        })
    }

    /// Gets the CryptoStream information.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the CryptoStream object.
    ///
    /// # Returns
    ///
    /// A tuple of (underlying_stream, transform, mode) if valid, or `None` otherwise.
    #[must_use]
    pub fn get_crypto_stream_info(&self, heap_ref: HeapRef) -> Option<(HeapRef, HeapRef, u8)> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::CryptoStream {
                underlying_stream,
                transform,
                mode,
                ..
            } => Some((*underlying_stream, *transform, *mode)),
            _ => None,
        }
    }

    /// Replaces an existing heap object with a CryptoStream object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object to replace.
    /// * `underlying_stream` - Reference to the underlying stream.
    /// * `transform` - Reference to the crypto transform.
    /// * `mode` - 0 for Read mode, 1 for Write mode.
    ///
    /// # Returns
    ///
    /// `true` if the object was replaced, `false` if the reference is invalid.
    pub fn replace_with_crypto_stream(
        &self,
        heap_ref: HeapRef,
        underlying_stream: HeapRef,
        transform: HeapRef,
        mode: u8,
    ) -> bool {
        let mut state = self.state.write().expect("heap lock poisoned");
        if let Some(old_obj) = state.objects.get(&heap_ref.id()) {
            let old_size = old_obj.estimated_size();
            let new_obj = HeapObject::CryptoStream {
                underlying_stream,
                transform,
                mode,
                transformed_data: None,
                transformed_pos: 0,
                write_buffer: Vec::new(),
            };
            let new_size = new_obj.estimated_size();
            state.objects.insert(heap_ref.id(), new_obj);

            // Update size tracking atomically
            if new_size >= old_size {
                self.current_size
                    .fetch_add(new_size - old_size, Ordering::Relaxed);
            } else {
                self.current_size
                    .fetch_sub(old_size - new_size, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    /// Gets the transformed data from a CryptoStream (if already cached).
    ///
    /// # Returns
    ///
    /// `Some((data, position))` if transformed data is cached, `None` otherwise.
    #[must_use]
    pub fn get_crypto_stream_transformed(&self, heap_ref: HeapRef) -> Option<(Vec<u8>, usize)> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::CryptoStream {
                transformed_data: Some(data),
                transformed_pos,
                ..
            } => Some((data.clone(), *transformed_pos)),
            _ => None,
        }
    }

    /// Sets the transformed data for a CryptoStream after transformation.
    ///
    /// This caches the decrypted/encrypted result for subsequent reads.
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if the reference is invalid or not a CryptoStream.
    pub fn set_crypto_stream_transformed(&self, heap_ref: HeapRef, data: Vec<u8>) -> bool {
        let mut state = self.state.write().expect("heap lock poisoned");
        let new_size = data.len();

        // Get old size first
        let old_size = match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CryptoStream {
                transformed_data, ..
            }) => transformed_data.as_ref().map_or(0, Vec::len),
            _ => return false,
        };

        // Mutate the object (imbl handles CoW internally)
        if let Some(HeapObject::CryptoStream {
            transformed_data,
            transformed_pos,
            ..
        }) = state.objects.get_mut(&heap_ref.id())
        {
            *transformed_data = Some(data);
            *transformed_pos = 0; // Reset position when setting new data
        } else {
            return false;
        }

        // Update size tracking atomically
        if new_size >= old_size {
            self.current_size
                .fetch_add(new_size - old_size, Ordering::Relaxed);
        } else {
            self.current_size
                .fetch_sub(old_size - new_size, Ordering::Relaxed);
        }
        true
    }

    /// Reads from a CryptoStream's transformed data, advancing the position.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the CryptoStream.
    /// * `count` - Maximum number of bytes to read.
    ///
    /// # Returns
    ///
    /// The bytes read (may be fewer than `count` if EOF reached), or `None`
    /// if the stream has no transformed data yet.
    pub fn read_crypto_stream(&self, heap_ref: HeapRef, count: usize) -> Option<Vec<u8>> {
        let mut state = self.state.write().expect("heap lock poisoned");
        if let Some(HeapObject::CryptoStream {
            transformed_data: Some(data),
            transformed_pos,
            ..
        }) = state.objects.get_mut(&heap_ref.id())
        {
            let available = data.len().saturating_sub(*transformed_pos);
            let to_read = count.min(available);
            let result = data[*transformed_pos..*transformed_pos + to_read].to_vec();
            *transformed_pos += to_read;
            Some(result)
        } else {
            None
        }
    }

    /// Appends data to a CryptoStream's write buffer (for Write mode).
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if the reference is invalid or not a CryptoStream.
    pub fn crypto_stream_append_write(&self, heap_ref: HeapRef, data: &[u8]) -> bool {
        let mut state = self.state.write().expect("heap lock poisoned");
        let data_len = data.len();

        // Mutate the object
        if let Some(HeapObject::CryptoStream { write_buffer, .. }) =
            state.objects.get_mut(&heap_ref.id())
        {
            write_buffer.extend_from_slice(data);
            // Update size tracking atomically
            self.current_size.fetch_add(data_len, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Gets the write buffer from a CryptoStream (for flushing).
    ///
    /// # Returns
    ///
    /// A copy of the write buffer, or `None` if not a CryptoStream.
    #[must_use]
    pub fn get_crypto_stream_write_buffer(&self, heap_ref: HeapRef) -> Option<Vec<u8>> {
        let state = self.state.read().expect("heap lock poisoned");
        match state.objects.get(&heap_ref.id())? {
            HeapObject::CryptoStream { write_buffer, .. } => Some(write_buffer.clone()),
            _ => None,
        }
    }

    /// Clears the write buffer after flushing.
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if the reference is invalid or not a CryptoStream.
    pub fn clear_crypto_stream_write_buffer(&self, heap_ref: HeapRef) -> bool {
        let mut state = self.state.write().expect("heap lock poisoned");

        // Get buffer size first
        let buffer_len = match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CryptoStream { write_buffer, .. }) => write_buffer.len(),
            _ => return false,
        };

        // Clear the buffer
        if let Some(HeapObject::CryptoStream { write_buffer, .. }) =
            state.objects.get_mut(&heap_ref.id())
        {
            write_buffer.clear();
        }

        // Update size atomically
        self.current_size.fetch_sub(buffer_len, Ordering::Relaxed);
        true
    }
}

impl Clone for ManagedHeap {
    fn clone(&self) -> Self {
        // Clone is the same as fork - O(1) due to imbl's structural sharing
        self.fork()
    }
}

impl Default for ManagedHeap {
    fn default() -> Self {
        Self::default_size()
    }
}

impl fmt::Display for ManagedHeap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.read().expect("heap lock poisoned");
        write!(
            f,
            "Heap({} objects, {}/{} bytes)",
            state.objects.len(),
            self.current_size.load(Ordering::Relaxed),
            self.max_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn test_heap_alloc_string() {
        let heap = ManagedHeap::new(1024 * 1024);

        let string_ref = heap.alloc_string("Hello, World!").unwrap();
        assert!(heap.contains(string_ref));

        let value = heap.get_string(string_ref).unwrap();
        assert_eq!(&*value, "Hello, World!");
    }

    #[test]
    fn test_heap_alloc_array() {
        let heap = ManagedHeap::new(1024 * 1024);

        let array_ref = heap.alloc_array(CilFlavor::I4, 10).unwrap();
        assert!(heap.contains(array_ref));

        let length = heap.get_array_length(array_ref).unwrap();
        assert_eq!(length, 10);

        // Elements should be default initialized
        let elem = heap.get_array_element(array_ref, 0).unwrap();
        assert_eq!(elem, EmValue::I32(0));
    }

    #[test]
    fn test_heap_array_operations() {
        let heap = ManagedHeap::new(1024 * 1024);

        let array_ref = heap.alloc_array(CilFlavor::I4, 5).unwrap();

        heap.set_array_element(array_ref, 2, EmValue::I32(42))
            .unwrap();
        let elem = heap.get_array_element(array_ref, 2).unwrap();
        assert_eq!(elem, EmValue::I32(42));

        // Out of bounds
        assert!(heap.get_array_element(array_ref, 10).is_err());
        assert!(heap
            .set_array_element(array_ref, 10, EmValue::I32(0))
            .is_err());
    }

    #[test]
    fn test_heap_alloc_object() {
        let heap = ManagedHeap::new(1024 * 1024);

        let type_token = Token::new(0x0200_0001);
        let field_token = Token::new(0x0400_0001);
        let obj_ref = heap
            .alloc_object_with_fields(type_token, &[(field_token, CilFlavor::I4)])
            .unwrap();

        // Field should be default initialized
        let field = heap.get_field(obj_ref, field_token).unwrap();
        assert_eq!(field, EmValue::I32(0));

        // Set field
        heap.set_field(obj_ref, field_token, EmValue::I32(42))
            .unwrap();
        let field = heap.get_field(obj_ref, field_token).unwrap();
        assert_eq!(field, EmValue::I32(42));
    }

    #[test]
    fn test_heap_boxing() {
        let heap = ManagedHeap::new(1024 * 1024);

        let type_token = Token::new(0x0200_0001);
        let boxed_ref = heap.alloc_boxed(type_token, EmValue::I32(42)).unwrap();

        let value = heap.unbox(boxed_ref).unwrap();
        assert_eq!(value, EmValue::I32(42));
    }

    #[test]
    fn test_heap_out_of_memory() {
        let heap = ManagedHeap::new(100); // Very small

        // Try to allocate large string
        let large_string = "A".repeat(1000);
        let result = heap.alloc_string(&large_string);
        assert!(matches!(
            result,
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::HeapMemoryLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_heap_invalid_reference() {
        let heap = ManagedHeap::new(1024 * 1024);

        let fake_ref = HeapRef::new(9999);
        assert!(heap.get(fake_ref).is_err());
        assert!(!heap.contains(fake_ref));
    }

    #[test]
    fn test_heap_type_mismatch() {
        let heap = ManagedHeap::new(1024 * 1024);

        let string_ref = heap.alloc_string("test").unwrap();

        // Try to get array element from string
        assert!(matches!(
            heap.get_array_element(string_ref, 0),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::HeapTypeMismatch { .. })
        ));
    }

    #[test]
    fn test_heap_clear() {
        let heap = ManagedHeap::new(1024 * 1024);

        heap.alloc_string("test").unwrap();
        heap.alloc_array(CilFlavor::I4, 10).unwrap();

        assert!(heap.object_count() > 0);

        heap.clear();
        assert_eq!(heap.object_count(), 0);
        assert_eq!(heap.current_size(), 0);
    }

    #[test]
    fn test_heap_display() {
        let heap = ManagedHeap::new(1024 * 1024);
        heap.alloc_string("test").unwrap();

        let display = format!("{heap}");
        assert!(display.contains("1 objects"));
    }

    #[test]
    fn test_heap_object_display() {
        let obj = HeapObject::String("test".into());
        assert!(format!("{obj}").contains("test"));

        let obj = HeapObject::Array {
            element_type: CilFlavor::I4,
            elements: vec![EmValue::I32(0); 5],
        };
        assert!(format!("{obj}").contains("5"));
    }

    #[test]
    fn test_heap_concurrent_access() {
        // Test that we can access the heap without borrow conflicts
        let heap = ManagedHeap::new(1024 * 1024);

        let s1 = heap.alloc_string("first").unwrap();
        let s2 = heap.alloc_string("second").unwrap();

        // Get both strings without borrow conflicts
        let str1 = heap.get_string(s1).unwrap();
        let str2 = heap.get_string(s2).unwrap();

        assert_eq!(&*str1, "first");
        assert_eq!(&*str2, "second");

        // Can still allocate while holding references
        let s3 = heap.alloc_string("third").unwrap();
        let str3 = heap.get_string(s3).unwrap();

        assert_eq!(&*str3, "third");
        // Original Arc references still valid
        assert_eq!(&*str1, "first");
    }

    #[test]
    fn test_heap_fork() {
        let heap = ManagedHeap::new(1024 * 1024);

        // Allocate some objects
        let s1 = heap.alloc_string("original").unwrap();
        let arr1 = heap.alloc_array(CilFlavor::I4, 5).unwrap();
        heap.set_array_element(arr1, 0, EmValue::I32(42)).unwrap();

        // Fork the heap
        let forked = heap.fork();

        // Both heaps should see the same data
        assert_eq!(heap.get_string(s1).unwrap().as_ref(), "original");
        assert_eq!(forked.get_string(s1).unwrap().as_ref(), "original");
        assert_eq!(heap.get_array_element(arr1, 0).unwrap(), EmValue::I32(42));
        assert_eq!(forked.get_array_element(arr1, 0).unwrap(), EmValue::I32(42));

        // Modify the forked heap
        forked
            .set_array_element(arr1, 0, EmValue::I32(100))
            .unwrap();
        let s2 = forked.alloc_string("forked").unwrap();

        // Original heap should be unchanged
        assert_eq!(heap.get_array_element(arr1, 0).unwrap(), EmValue::I32(42));
        assert!(!heap.contains(s2));

        // Forked heap should have the new values
        assert_eq!(
            forked.get_array_element(arr1, 0).unwrap(),
            EmValue::I32(100)
        );
        assert!(forked.contains(s2));
        assert_eq!(forked.get_string(s2).unwrap().as_ref(), "forked");
    }

    #[test]
    fn test_heap_fork_isolation() {
        let heap = ManagedHeap::new(1024 * 1024);

        // Allocate in original
        let s1 = heap.alloc_string("hello").unwrap();

        // Create multiple forks
        let fork1 = heap.fork();
        let fork2 = heap.fork();

        // Allocate in each fork - they will get the same IDs since they
        // started from the same next_id, but the objects are independent
        let f1_str = fork1.alloc_string("fork1").unwrap();
        let f2_str = fork2.alloc_string("fork2").unwrap();

        // Both forks see the original string
        assert!(fork1.contains(s1));
        assert!(fork2.contains(s1));
        assert_eq!(fork1.get_string(s1).unwrap().as_ref(), "hello");
        assert_eq!(fork2.get_string(s1).unwrap().as_ref(), "hello");

        // Each fork sees its own allocation (with the same ID, but different content)
        assert_eq!(fork1.get_string(f1_str).unwrap().as_ref(), "fork1");
        assert_eq!(fork2.get_string(f2_str).unwrap().as_ref(), "fork2");

        // Original should not see any fork allocations
        // (the IDs are the same, but original doesn't have those objects)
        assert!(heap.contains(s1));
        assert!(!heap.contains(f1_str)); // ID 2 doesn't exist in original
    }

    #[test]
    fn test_heap_fork_cow_semantics() {
        let heap = ManagedHeap::new(1024 * 1024);

        // Allocate an array
        let arr = heap.alloc_array(CilFlavor::I4, 3).unwrap();
        heap.set_array_element(arr, 0, EmValue::I32(1)).unwrap();
        heap.set_array_element(arr, 1, EmValue::I32(2)).unwrap();
        heap.set_array_element(arr, 2, EmValue::I32(3)).unwrap();

        // Fork
        let forked = heap.fork();

        // Both see the same initial values
        assert_eq!(heap.get_array_element(arr, 0).unwrap(), EmValue::I32(1));
        assert_eq!(forked.get_array_element(arr, 0).unwrap(), EmValue::I32(1));

        // Modify in forked - this triggers CoW at the data structure level
        forked.set_array_element(arr, 0, EmValue::I32(100)).unwrap();

        // Original is unchanged (CoW worked!)
        assert_eq!(heap.get_array_element(arr, 0).unwrap(), EmValue::I32(1));
        assert_eq!(heap.get_array_element(arr, 1).unwrap(), EmValue::I32(2));
        assert_eq!(heap.get_array_element(arr, 2).unwrap(), EmValue::I32(3));

        // Forked has the new value
        assert_eq!(forked.get_array_element(arr, 0).unwrap(), EmValue::I32(100));
        // But other elements are still shared (at the object level, not imbl level)
        assert_eq!(forked.get_array_element(arr, 1).unwrap(), EmValue::I32(2));
        assert_eq!(forked.get_array_element(arr, 2).unwrap(), EmValue::I32(3));
    }
}
