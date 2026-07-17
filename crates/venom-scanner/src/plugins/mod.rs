//! Vulnerability Scanner Plugins
//!
//! Modular plugin implementations for various vulnerability types.

pub mod xss;
pub mod sqli;
pub mod lfi;
pub mod xxe;
pub mod ssrf;
pub mod ssti;

pub use xss::XSSPlugin;
pub use sqli::SQLiPlugin;
pub use lfi::LFIPlugin;
pub use xxe::XXEPlugin;
pub use ssrf::SSRFPlugin;
pub use ssti::SSTIPlugin;
