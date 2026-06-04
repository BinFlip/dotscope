//! Unified work queue for deobfuscation pipeline work items.
//!
//! The [`WorkQueue`] provides a thread-safe queue for submitting and draining
//! work items that represent pending transformations, SSA builds, and re-detection
//! requests. Deduplication is enforced at enqueue time through categorized storage.

use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::{DashMap, DashSet};
use log::warn;

use crate::{
    analysis::SsaFunction,
    metadata::token::Token,
    {Error, Result},
};

/// A work item representing a pending operation in the deobfuscation pipeline.
#[derive(Debug)]
pub enum WorkItem {
    /// Request to build SSA for a set of methods.
    BuildSsa(Vec<Token>),
    /// Inject a pre-built SSA function into the pipeline.
    InjectSsa {
        /// The method token this SSA function belongs to.
        token: Token,
        /// The pre-built SSA function (boxed due to large size).
        function: Box<SsaFunction>,
    },
    /// Re-detect specific methods.
    RedetectMethods(Vec<Token>),
    /// Re-detect specific types.
    RedetectTypes(Vec<Token>),
    /// Re-detect the entire assembly.
    RedetectAssembly,
}

/// Result of draining the work queue.
///
/// Contains categorized, pre-deduplicated work items ready for processing.
#[derive(Debug)]
pub struct DrainedWorkItems {
    /// Methods needing SSA construction.
    pub build_ssa: Vec<Token>,
    /// Pre-built SSA functions to inject.
    pub inject_ssa: Vec<(Token, Box<SsaFunction>)>,
    /// Methods to re-detect.
    pub redetect_methods: Vec<Token>,
    /// Types to re-detect.
    pub redetect_types: Vec<Token>,
    /// Whether to re-detect the entire assembly.
    pub redetect_assembly: bool,
}

impl DrainedWorkItems {
    /// Returns `true` if there are no pending work items.
    pub fn is_empty(&self) -> bool {
        self.build_ssa.is_empty()
            && self.inject_ssa.is_empty()
            && self.redetect_methods.is_empty()
            && self.redetect_types.is_empty()
            && !self.redetect_assembly
    }

    /// Returns `true` if any re-detection is requested.
    pub fn has_redetect(&self) -> bool {
        !self.redetect_methods.is_empty()
            || !self.redetect_types.is_empty()
            || self.redetect_assembly
    }
}

/// Thread-safe work queue for deobfuscation pipeline items.
///
/// Work items are submitted by techniques and passes during processing, then
/// drained by the engine between pipeline phases. Deduplication is enforced
/// at enqueue time through categorized storage.
pub struct WorkQueue {
    build_ssa: DashSet<Token>,
    inject_ssa: DashMap<Token, Box<SsaFunction>>,
    redetect_methods: DashSet<Token>,
    redetect_types: DashSet<Token>,
    redetect_assembly: AtomicBool,
}

impl WorkQueue {
    /// Creates a new empty work queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            build_ssa: DashSet::new(),
            inject_ssa: DashMap::new(),
            redetect_methods: DashSet::new(),
            redetect_types: DashSet::new(),
            redetect_assembly: AtomicBool::new(false),
        }
    }

    /// Submits a single work item to the queue.
    ///
    /// Deduplication is enforced at enqueue time:
    /// - `BuildSsa` tokens are inserted into a `DashSet` (duplicates ignored).
    /// - `InjectSsa` entries are keyed by token; submitting a duplicate returns `Err`.
    /// - `RedetectMethods` / `RedetectTypes` tokens are inserted into `DashSet`s.
    /// - `RedetectAssembly` sets an atomic flag.
    pub fn submit(&self, item: WorkItem) -> Result<()> {
        match item {
            WorkItem::BuildSsa(tokens) => {
                for token in tokens {
                    self.build_ssa.insert(token);
                }
            }
            WorkItem::InjectSsa { token, function } => {
                if self.inject_ssa.contains_key(&token) {
                    warn!(
                        "Duplicate InjectSsa for token {}, rejecting submission",
                        token
                    );
                    return Err(Error::Deobfuscation(format!(
                        "Duplicate InjectSsa for token {token}"
                    )));
                }
                self.inject_ssa.insert(token, function);
            }
            WorkItem::RedetectMethods(tokens) => {
                for token in tokens {
                    self.redetect_methods.insert(token);
                }
            }
            WorkItem::RedetectTypes(tokens) => {
                for token in tokens {
                    self.redetect_types.insert(token);
                }
            }
            WorkItem::RedetectAssembly => {
                self.redetect_assembly.store(true, Ordering::Release);
            }
        }
        Ok(())
    }

    /// Submits multiple work items to the queue.
    ///
    /// Each item is submitted individually via [`submit()`](Self::submit).
    /// If any submission fails, the error is returned immediately and remaining
    /// items are not submitted.
    pub fn submit_all(&self, items: impl IntoIterator<Item = WorkItem>) -> Result<()> {
        for item in items {
            self.submit(item)?;
        }
        Ok(())
    }

    /// Drains all pending work items from the queue, returning them as a
    /// categorized [`DrainedWorkItems`] struct.
    ///
    /// All internal collections are emptied and the `redetect_assembly` flag
    /// is swapped to `false`.
    pub fn drain(&self) -> DrainedWorkItems {
        // DashSet/DashMap don't have drain(), so we collect then clear.
        let build_ssa: Vec<Token> = self.build_ssa.iter().map(|r| *r).collect();
        self.build_ssa.clear();

        let inject_ssa: Vec<(Token, Box<SsaFunction>)> = self
            .inject_ssa
            .iter()
            .map(|r| *r.key())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|k| self.inject_ssa.remove(&k))
            .collect();

        let redetect_methods: Vec<Token> = self.redetect_methods.iter().map(|r| *r).collect();
        self.redetect_methods.clear();

        let redetect_types: Vec<Token> = self.redetect_types.iter().map(|r| *r).collect();
        self.redetect_types.clear();

        let redetect_assembly = self.redetect_assembly.swap(false, Ordering::AcqRel);

        DrainedWorkItems {
            build_ssa,
            inject_ssa,
            redetect_methods,
            redetect_types,
            redetect_assembly,
        }
    }

    /// Returns `true` if the queue has no pending items.
    pub fn is_empty(&self) -> bool {
        self.build_ssa.is_empty()
            && self.inject_ssa.is_empty()
            && self.redetect_methods.is_empty()
            && self.redetect_types.is_empty()
            && !self.redetect_assembly.load(Ordering::Acquire)
    }

    /// Returns the number of pending items in the queue.
    ///
    /// The count is the sum of all category sizes. For `redetect_assembly`,
    /// it counts as 1 if the flag is set.
    pub fn len(&self) -> usize {
        let assembly = usize::from(self.redetect_assembly.load(Ordering::Acquire));
        self.build_ssa
            .len()
            .saturating_add(self.inject_ssa.len())
            .saturating_add(self.redetect_methods.len())
            .saturating_add(self.redetect_types.len())
            .saturating_add(assembly)
    }
}

impl Default for WorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::SsaFunction,
        deobfuscation::workqueue::{WorkItem, WorkQueue},
        metadata::token::Token,
    };

    #[test]
    fn test_submit_and_drain() {
        let queue = WorkQueue::new();

        queue
            .submit(WorkItem::BuildSsa(vec![Token::new(0x06000001)]))
            .unwrap();
        queue.submit(WorkItem::RedetectAssembly).unwrap();

        let items = queue.drain();

        // BuildSsa should contain our token
        assert_eq!(items.build_ssa.len(), 1);
        assert!(items.build_ssa.contains(&Token::new(0x06000001)));

        // RedetectAssembly should be set
        assert!(items.redetect_assembly);

        // Queue should be empty after drain
        assert!(queue.is_empty());
    }

    #[test]
    fn test_submit_all() {
        let queue = WorkQueue::new();

        let items = vec![
            WorkItem::BuildSsa(vec![Token::new(0x06000001)]),
            WorkItem::BuildSsa(vec![Token::new(0x06000002)]),
        ];

        queue.submit_all(items).unwrap();
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_drain_empty() {
        let queue = WorkQueue::new();
        let items = queue.drain();
        assert!(items.is_empty());
    }

    #[test]
    fn test_thread_safety() {
        let queue = Arc::new(WorkQueue::new());
        let mut handles = Vec::new();

        for i in 0..4 {
            let queue = Arc::clone(&queue);
            handles.push(std::thread::spawn(move || {
                for j in 0..25 {
                    queue
                        .submit(WorkItem::BuildSsa(vec![Token::new(
                            0x06000000 + i * 100 + j,
                        )]))
                        .unwrap();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All 100 tokens are unique, so dedup should keep all of them
        assert_eq!(queue.len(), 100);

        let items = queue.drain();
        assert_eq!(items.build_ssa.len(), 100);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_is_empty_and_len() {
        let queue = WorkQueue::new();

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue
            .submit(WorkItem::RedetectMethods(vec![Token::new(0x06000001)]))
            .unwrap();

        assert!(!queue.is_empty());
        assert_eq!(queue.len(), 1);

        queue.drain();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_build_ssa_dedup() {
        let queue = WorkQueue::new();

        // Submit the same token multiple times across multiple calls
        queue
            .submit(WorkItem::BuildSsa(vec![
                Token::new(0x06000001),
                Token::new(0x06000002),
            ]))
            .unwrap();
        queue
            .submit(WorkItem::BuildSsa(vec![
                Token::new(0x06000002),
                Token::new(0x06000003),
            ]))
            .unwrap();
        queue
            .submit(WorkItem::BuildSsa(vec![Token::new(0x06000001)]))
            .unwrap();

        let items = queue.drain();

        // Should have exactly 3 unique tokens
        assert_eq!(items.build_ssa.len(), 3);
        assert!(items.build_ssa.contains(&Token::new(0x06000001)));
        assert!(items.build_ssa.contains(&Token::new(0x06000002)));
        assert!(items.build_ssa.contains(&Token::new(0x06000003)));
    }

    #[test]
    fn test_inject_ssa_conflict() {
        let queue = WorkQueue::new();
        let token = Token::new(0x06000001);

        // First injection should succeed
        queue
            .submit(WorkItem::InjectSsa {
                token,
                function: Box::new(SsaFunction::new(0, 0)),
            })
            .unwrap();

        // Second injection for the same token should fail
        let result = queue.submit(WorkItem::InjectSsa {
            token,
            function: Box::new(SsaFunction::new(0, 0)),
        });
        assert!(result.is_err());

        // The first injection should still be present
        let items = queue.drain();
        assert_eq!(items.inject_ssa.len(), 1);
        assert_eq!(items.inject_ssa[0].0, token);
    }

    #[test]
    fn test_redetect_methods_dedup() {
        let queue = WorkQueue::new();

        queue
            .submit(WorkItem::RedetectMethods(vec![
                Token::new(0x06000001),
                Token::new(0x06000002),
            ]))
            .unwrap();
        queue
            .submit(WorkItem::RedetectMethods(vec![
                Token::new(0x06000002),
                Token::new(0x06000003),
            ]))
            .unwrap();

        let items = queue.drain();
        assert_eq!(items.redetect_methods.len(), 3);
    }

    #[test]
    fn test_redetect_types_dedup() {
        let queue = WorkQueue::new();

        queue
            .submit(WorkItem::RedetectTypes(vec![
                Token::new(0x02000001),
                Token::new(0x02000002),
            ]))
            .unwrap();
        queue
            .submit(WorkItem::RedetectTypes(vec![Token::new(0x02000002)]))
            .unwrap();

        let items = queue.drain();
        assert_eq!(items.redetect_types.len(), 2);
    }

    #[test]
    fn test_redetect_assembly_flag() {
        let queue = WorkQueue::new();

        // Submit assembly redetect multiple times — should only count as 1
        queue.submit(WorkItem::RedetectAssembly).unwrap();
        queue.submit(WorkItem::RedetectAssembly).unwrap();

        assert_eq!(queue.len(), 1);

        let items = queue.drain();
        assert!(items.redetect_assembly);

        // After drain, the flag should be cleared
        assert!(queue.is_empty());
        let items2 = queue.drain();
        assert!(!items2.redetect_assembly);
    }

    #[test]
    fn test_drained_work_items_is_empty() {
        let queue = WorkQueue::new();
        let items = queue.drain();
        assert!(items.is_empty());

        queue
            .submit(WorkItem::BuildSsa(vec![Token::new(0x06000001)]))
            .unwrap();
        let items = queue.drain();
        assert!(!items.is_empty());
    }

    #[test]
    fn test_drained_work_items_has_redetect() {
        let queue = WorkQueue::new();

        // No redetect items
        queue
            .submit(WorkItem::BuildSsa(vec![Token::new(0x06000001)]))
            .unwrap();
        let items = queue.drain();
        assert!(!items.has_redetect());

        // With redetect methods
        queue
            .submit(WorkItem::RedetectMethods(vec![Token::new(0x06000001)]))
            .unwrap();
        let items = queue.drain();
        assert!(items.has_redetect());

        // With redetect types
        queue
            .submit(WorkItem::RedetectTypes(vec![Token::new(0x02000001)]))
            .unwrap();
        let items = queue.drain();
        assert!(items.has_redetect());

        // With redetect assembly
        queue.submit(WorkItem::RedetectAssembly).unwrap();
        let items = queue.drain();
        assert!(items.has_redetect());
    }
}
