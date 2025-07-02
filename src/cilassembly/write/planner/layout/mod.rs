//! Comprehensive layout planning module for binary generation.
//!
//! This module provides all layout-related functionality for .NET assembly binary generation,
//! organized into focused sub-modules for each layout concept. It implements a type-driven
//! approach where layout types provide rich methods for creation, analysis, and modification.
//!
//! # Module Structure
//!
//! - [`file`] - FileLayout and related file structure planning
//! - [`plan`] - LayoutPlan and overall layout orchestration  
//! - [`section`] - SectionFileLayout and section-specific logic
//! - [`stream`] - StreamFileLayout and metadata stream planning
//! - [`region`] - FileRegion utilities for file positioning
//!
//! # Architecture
//!
//! The layout module follows a type-driven design where each layout type encapsulates
//! its related functionality as methods rather than external functions. This creates
//! more discoverable and intuitive APIs.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::layout::{FileLayout, LayoutPlan};
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! // Create a complete layout plan
//! let layout_plan = LayoutPlan::create(&assembly)?;
//!
//! // Access file layout with rich methods
//! let file_layout = &layout_plan.file_layout;
//! let metadata_section = file_layout.find_metadata_section()?;
//! let total_size = file_layout.calculate_total_size(&assembly)?;
//!
//! // Work with streams in a type-driven way
//! let strings_stream = metadata_section.find_stream_layout("#Strings")?;
//! # Ok::<(), crate::Error>(())
//! ```

mod file;
mod plan;
mod region;
mod section;
mod stream;

pub use file::FileLayout;
pub use plan::LayoutPlan;
pub use region::FileRegion;
pub use section::SectionFileLayout;
pub use stream::StreamFileLayout;
