//! Stream type operations for the managed heap.
//!
//! This module provides operations for Stream (MemoryStream), CryptoStream,
//! and CompressedStream (DeflateStream/GZipStream) objects on [`ManagedHeap`].

use std::sync::atomic::Ordering;

use crate::{
    emulation::{
        engine::EmulationError,
        memory::heap::{HeapObject, ManagedHeap},
        HeapRef,
    },
    metadata::token::Token,
    Result,
};

impl ManagedHeap {
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
    pub fn alloc_stream(&self, data: Vec<u8>, type_token: Option<Token>) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::Stream { data, position: 0 }, type_token)
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
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_stream_data(&self, heap_ref: HeapRef) -> Result<Option<(Vec<u8>, usize)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Stream { data, position }) => Some((data.clone(), *position)),
            _ => None,
        })
    }

    /// Reads a single byte from a stream and advances the position by 1.
    ///
    /// Returns `None` if the reference is not a stream or if at EOF.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stream_read_byte(&self, heap_ref: HeapRef) -> Result<Option<u8>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stream { data, position }) = state.objects.get_mut(&heap_ref.id()) {
            if *position < data.len() {
                let byte = data[*position];
                *position += 1;
                return Ok(Some(byte));
            }
        }
        Ok(None)
    }

    /// Reads exactly `N` bytes from a stream and advances the position.
    ///
    /// Returns `None` if the reference is not a stream or if fewer than `N` bytes remain.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stream_read_exact<const N: usize>(&self, heap_ref: HeapRef) -> Result<Option<[u8; N]>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stream { data, position }) = state.objects.get_mut(&heap_ref.id()) {
            if *position + N <= data.len() {
                let mut buf = [0u8; N];
                buf.copy_from_slice(&data[*position..*position + N]);
                *position += N;
                return Ok(Some(buf));
            }
        }
        Ok(None)
    }

    /// Reads up to `count` bytes from a stream and advances the position.
    ///
    /// Returns fewer than `count` bytes if at or near EOF.
    /// Returns `None` if the reference is not a stream.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stream_read(&self, heap_ref: HeapRef, count: usize) -> Result<Option<Vec<u8>>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stream { data, position }) = state.objects.get_mut(&heap_ref.id()) {
            let available = data.len().saturating_sub(*position);
            let to_read = count.min(available);
            let bytes = data[*position..*position + to_read].to_vec();
            *position += to_read;
            return Ok(Some(bytes));
        }
        Ok(None)
    }

    /// Returns the length of a stream without cloning the data.
    ///
    /// Returns `None` if the reference is not a stream.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stream_len(&self, heap_ref: HeapRef) -> Result<Option<usize>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stream { data, .. }) = state.objects.get(&heap_ref.id()) {
            return Ok(Some(data.len()));
        }
        Ok(None)
    }

    /// Returns the current position of a stream without cloning the data.
    ///
    /// Returns `None` if the reference is not a stream.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stream_position(&self, heap_ref: HeapRef) -> Result<Option<usize>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stream { position, .. }) = state.objects.get(&heap_ref.id()) {
            return Ok(Some(*position));
        }
        Ok(None)
    }

    /// Executes a closure with direct access to a stream's data and mutable position.
    ///
    /// The closure receives `(&[u8], &mut usize)` — the data buffer and mutable
    /// position reference. This allows complex multi-byte reads (e.g. 7-bit encoded
    /// integers) without cloning the entire buffer.
    ///
    /// Returns `None` if the reference is not a stream.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn with_stream<F, R>(&self, heap_ref: HeapRef, f: F) -> Result<Option<R>>
    where
        F: FnOnce(&[u8], &mut usize) -> R,
    {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stream { data, position }) = state.objects.get_mut(&heap_ref.id()) {
            return Ok(Some(f(data, position)));
        }
        Ok(None)
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
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn set_stream_position(&self, heap_ref: HeapRef, new_position: usize) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stream { position, .. }) = state.objects.get_mut(&heap_ref.id()) {
            *position = new_position;
            Ok(true)
        } else {
            Ok(false)
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
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn write_to_stream(&self, heap_ref: HeapRef, bytes: &[u8]) -> Result<usize> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
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

            Ok(write_len)
        } else {
            Ok(0)
        }
    }

    /// Truncates or extends the stream to the given length.
    ///
    /// If the new length is shorter than the current data, the data is truncated.
    /// If longer, the data is zero-extended. The position is clamped to the new length.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the stream object.
    /// * `new_length` - The desired length.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn truncate_stream(&self, heap_ref: HeapRef, new_length: usize) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stream { data, position }) = state.objects.get_mut(&heap_ref.id()) {
            data.resize(new_length, 0);
            if *position > new_length {
                *position = new_length;
            }
        }
        Ok(())
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
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn replace_with_stream(&self, heap_ref: HeapRef, data: Vec<u8>) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);

        if let Some(old_obj) = state.objects.get(&id) {
            let old_size = old_obj.estimated_size();
            let new_obj = HeapObject::Stream { data, position: 0 };
            let new_size = new_obj.estimated_size();
            state.objects.insert(id, new_obj);

            // Update size tracking atomically
            if new_size >= old_size {
                self.current_size
                    .fetch_add(new_size - old_size, Ordering::Relaxed);
            } else {
                self.current_size
                    .fetch_sub(old_size - new_size, Ordering::Relaxed);
            }
            Ok(true)
        } else {
            Ok(false)
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
        type_token: Option<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::CryptoStream {
                underlying_stream,
                transform,
                mode,
                transformed_data: None,
                transformed_pos: 0,
                write_buffer: Vec::new(),
            },
            type_token,
        )
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
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_crypto_stream_info(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<(HeapRef, HeapRef, u8)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CryptoStream {
                underlying_stream,
                transform,
                mode,
                ..
            }) => Some((*underlying_stream, *transform, *mode)),
            _ => None,
        })
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
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn replace_with_crypto_stream(
        &self,
        heap_ref: HeapRef,
        underlying_stream: HeapRef,
        transform: HeapRef,
        mode: u8,
    ) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);
        if let Some(old_obj) = state.objects.get(&id) {
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
            state.objects.insert(id, new_obj);

            // Update size tracking atomically
            if new_size >= old_size {
                self.current_size
                    .fetch_add(new_size - old_size, Ordering::Relaxed);
            } else {
                self.current_size
                    .fetch_sub(old_size - new_size, Ordering::Relaxed);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Gets the transformed data from a CryptoStream (if already cached).
    ///
    /// # Returns
    ///
    /// `Some((data, position))` if transformed data is cached, `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_crypto_stream_transformed(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<(Vec<u8>, usize)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CryptoStream {
                transformed_data: Some(data),
                transformed_pos,
                ..
            }) => Some((data.clone(), *transformed_pos)),
            _ => None,
        })
    }

    /// Sets the transformed data for a CryptoStream after transformation.
    ///
    /// This caches the decrypted/encrypted result for subsequent reads.
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if the reference is invalid or not a CryptoStream.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn set_crypto_stream_transformed(&self, heap_ref: HeapRef, data: Vec<u8>) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let new_size = data.len();

        // Get old size first
        let old_size = match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CryptoStream {
                transformed_data, ..
            }) => transformed_data.as_ref().map_or(0, Vec::len),
            _ => return Ok(false),
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
            return Ok(false);
        }

        // Update size tracking atomically
        if new_size >= old_size {
            self.current_size
                .fetch_add(new_size - old_size, Ordering::Relaxed);
        } else {
            self.current_size
                .fetch_sub(old_size - new_size, Ordering::Relaxed);
        }
        Ok(true)
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
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn read_crypto_stream(&self, heap_ref: HeapRef, count: usize) -> Result<Option<Vec<u8>>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
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
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Appends data to a CryptoStream's write buffer (for Write mode).
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if the reference is invalid or not a CryptoStream.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn crypto_stream_append_write(&self, heap_ref: HeapRef, data: &[u8]) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let data_len = data.len();

        // Mutate the object
        if let Some(HeapObject::CryptoStream { write_buffer, .. }) =
            state.objects.get_mut(&heap_ref.id())
        {
            write_buffer.extend_from_slice(data);
            // Update size tracking atomically
            self.current_size.fetch_add(data_len, Ordering::Relaxed);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Gets the write buffer from a CryptoStream (for flushing).
    ///
    /// # Returns
    ///
    /// A copy of the write buffer, or `None` if not a CryptoStream.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_crypto_stream_write_buffer(&self, heap_ref: HeapRef) -> Result<Option<Vec<u8>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CryptoStream { write_buffer, .. }) => Some(write_buffer.clone()),
            _ => None,
        })
    }

    /// Clears the write buffer after flushing.
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if the reference is invalid or not a CryptoStream.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn clear_crypto_stream_write_buffer(&self, heap_ref: HeapRef) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;

        // Get buffer size first
        let buffer_len = match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CryptoStream { write_buffer, .. }) => write_buffer.len(),
            _ => return Ok(false),
        };

        // Clear the buffer
        if let Some(HeapObject::CryptoStream { write_buffer, .. }) =
            state.objects.get_mut(&heap_ref.id())
        {
            write_buffer.clear();
        }

        // Update size atomically
        self.current_size.fetch_sub(buffer_len, Ordering::Relaxed);
        Ok(true)
    }

    /// Replaces an existing heap object with a CompressedStream.
    ///
    /// Used when a `DeflateStream` or `GZipStream` is constructed on top of
    /// an already-allocated object (instance constructor pattern).
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object to replace.
    /// * `underlying_stream` - Reference to the underlying stream containing compressed data.
    /// * `compression_type` - 0 for Deflate, 1 for GZip.
    /// * `mode` - 0 for Decompress, 1 for Compress.
    ///
    /// # Returns
    ///
    /// `true` if the object was replaced, `false` if the reference is invalid.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn replace_with_compressed_stream(
        &self,
        heap_ref: HeapRef,
        underlying_stream: HeapRef,
        compression_type: u8,
        mode: u8,
    ) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);
        if let Some(old_obj) = state.objects.get(&id) {
            let old_size = old_obj.estimated_size();
            let new_obj = HeapObject::CompressedStream {
                underlying_stream,
                compression_type,
                mode,
                decompressed_data: None,
                read_position: 0,
            };
            let new_size = new_obj.estimated_size();
            state.objects.insert(id, new_obj);

            // Update size tracking atomically
            if new_size >= old_size {
                self.current_size
                    .fetch_add(new_size - old_size, Ordering::Relaxed);
            } else {
                self.current_size
                    .fetch_sub(old_size - new_size, Ordering::Relaxed);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Gets info about a CompressedStream: (underlying_stream, compression_type, mode).
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the CompressedStream object.
    ///
    /// # Returns
    ///
    /// `Some((underlying_stream, compression_type, mode))` if the object is a CompressedStream,
    /// `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_compressed_stream_info(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<(HeapRef, u8, u8)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CompressedStream {
                underlying_stream,
                compression_type,
                mode,
                ..
            }) => Some((*underlying_stream, *compression_type, *mode)),
            _ => None,
        })
    }

    /// Sets the decompressed data cache for a CompressedStream.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the CompressedStream object.
    /// * `data` - The decompressed data to cache.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn set_compressed_stream_data(&self, heap_ref: HeapRef, data: Vec<u8>) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let data_len = data.len();

        // Get old cached size
        let old_cached_size = match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::CompressedStream {
                decompressed_data, ..
            }) => decompressed_data.as_ref().map_or(0, Vec::len),
            _ => return Ok(()),
        };

        if let Some(HeapObject::CompressedStream {
            decompressed_data, ..
        }) = state.objects.get_mut(&heap_ref.id())
        {
            *decompressed_data = Some(data);
        }

        // Update size tracking atomically
        if data_len >= old_cached_size {
            self.current_size
                .fetch_add(data_len - old_cached_size, Ordering::Relaxed);
        } else {
            self.current_size
                .fetch_sub(old_cached_size - data_len, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Reads bytes from a CompressedStream's decompressed cache.
    ///
    /// Returns the bytes read and advances the read position.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the CompressedStream object.
    /// * `count` - Maximum number of bytes to read.
    ///
    /// # Returns
    ///
    /// The bytes read (may be fewer than `count` if EOF reached), or `None`
    /// if the stream has no decompressed data yet.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn read_compressed_stream(
        &self,
        heap_ref: HeapRef,
        count: usize,
    ) -> Result<Option<Vec<u8>>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get_mut(&heap_ref.id()) {
            Some(HeapObject::CompressedStream {
                decompressed_data: Some(data),
                read_position,
                ..
            }) => {
                let available = data.len().saturating_sub(*read_position);
                let to_read = count.min(available);
                let bytes = data[*read_position..*read_position + to_read].to_vec();
                *read_position += to_read;
                Some(bytes)
            }
            _ => None,
        })
    }

    /// Checks if a CompressedStream has cached decompressed data.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the CompressedStream object.
    ///
    /// # Returns
    ///
    /// `true` if the CompressedStream has cached decompressed data, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn has_compressed_stream_data(&self, heap_ref: HeapRef) -> Result<bool> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(matches!(
            state.objects.get(&heap_ref.id()),
            Some(HeapObject::CompressedStream {
                decompressed_data: Some(_),
                ..
            })
        ))
    }
}
