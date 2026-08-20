//! Concrete adapters: development stub and future OpenMLS bridge.

pub mod stub;

#[cfg(feature = "openmls")]
pub mod openmls_adapter;
