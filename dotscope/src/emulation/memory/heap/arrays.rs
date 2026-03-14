//! Array type operations for the managed heap.
//!
//! This module provides operations for single-dimensional arrays, multi-dimensional
//! arrays, and byte array convenience methods on [`ManagedHeap`].

use crate::{
    emulation::{
        engine::EmulationError,
        memory::heap::{HeapObject, ManagedHeap},
        EmValue, HeapRef,
    },
    metadata::typesystem::{CilFlavor, PointerSize},
    Result,
};

impl ManagedHeap {
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
        self.alloc_object_internal(
            HeapObject::Array {
                element_type,
                elements,
            },
            None,
        )
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
        self.alloc_object_internal(
            HeapObject::Array {
                element_type,
                elements,
            },
            None,
        )
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
        self.alloc_object_internal(
            HeapObject::MultiArray {
                element_type,
                dimensions,
                elements,
            },
            None,
        )
    }

    /// Gets an array element (cloned).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid, not an array, or index out of bounds.
    pub fn get_array_element(&self, heap_ref: HeapRef, index: usize) -> Result<EmValue> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
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
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid, not an array, or index out of bounds.
    pub fn set_array_element(&self, heap_ref: HeapRef, index: usize, value: EmValue) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
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
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not an array.
    pub fn get_array_length(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
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
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not an array.
    pub fn get_array_element_type(&self, heap_ref: HeapRef) -> Result<CilFlavor> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()) {
            Some(
                HeapObject::Array { element_type, .. }
                | HeapObject::MultiArray { element_type, .. },
            ) => Ok(element_type.clone()),
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
    /// Returns `Ok(None)` if the reference is invalid, not a byte array, or contains
    /// any non-I32 elements (including Symbolic values). This fail-fast behavior
    /// ensures callers don't silently receive partial/corrupted data.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn get_byte_array(&self, heap_ref: HeapRef) -> Result<Option<Vec<u8>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Array { elements, .. }) => {
                let mut bytes = Vec::with_capacity(elements.len());
                for e in elements {
                    match e {
                        EmValue::I32(n) => bytes.push(*n as u8),
                        _ => return Ok(None),
                    }
                }
                Some(bytes)
            }
            _ => None,
        })
    }

    /// Converts an array's elements to a byte vector, respecting element type.
    ///
    /// Unlike `get_byte_array` which only takes the low byte, this method
    /// properly serializes multi-byte elements (uint32, int64, etc.) to bytes
    /// in little-endian order.
    ///
    /// Returns `Ok(None)` if the reference is invalid, not an array, or contains
    /// non-numeric types.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn get_array_as_bytes(
        &self,
        heap_ref: HeapRef,
        ptr_size: PointerSize,
    ) -> Result<Option<Vec<u8>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Array {
                elements,
                element_type,
            }) => {
                let element_size = element_type.element_size(ptr_size);
                match element_size {
                    Some(element_size) => {
                        let mut bytes = Vec::with_capacity(elements.len() * element_size);
                        let mut valid = true;
                        for e in elements {
                            match e {
                                EmValue::I32(n) => match element_size {
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
                                _ => {
                                    valid = false;
                                    break;
                                }
                            }
                        }
                        if valid {
                            Some(bytes)
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            }
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{memory::heap::ManagedHeap, EmValue},
        metadata::typesystem::CilFlavor,
    };

    #[test]
    fn test_heap_alloc_array() {
        let heap = ManagedHeap::new(1024 * 1024);

        let array_ref = heap.alloc_array(CilFlavor::I4, 10).unwrap();
        assert!(heap.contains(array_ref).unwrap());

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
}
