//! Storage traits for SafeHub's three server-side services.
//!
//! 1. **Blob store** — content-addressed encrypted chunks (S3-compatible later)
//! 2. **Head log** — compare-and-swap ref-head chain
//! 3. **MLS delivery** — ordered opaque framing fan-out
//!
//! [`local`] provides a filesystem backend for development; production will
//! swap in an object-store implementation without changing the API surface.

#![deny(missing_docs)]

pub mod error;
pub mod local;
pub mod traits;

pub use error::StorageError;
pub use local::LocalStore;
pub use traits::{BlobStore, HeadLog, MlsDeliveryQueue, RepoDirectory};
