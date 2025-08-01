#[cfg(all(feature = "jemalloc", unix))]
use jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

pub mod auth;
pub mod certificates;
pub mod config;
pub mod constants;
pub mod network;
pub mod socket;
pub mod utils;
