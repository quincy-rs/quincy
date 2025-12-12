#[cfg(all(feature = "jemalloc", unix))]
use jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

pub mod auth;
pub mod certificates;
pub mod config;
pub mod constants;
pub mod error;
pub mod network;
pub mod utils;

// Re-export common types for convenience
pub use error::{QuincyError, Result};
