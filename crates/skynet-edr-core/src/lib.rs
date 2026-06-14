//! Platform-independent core primitives for Skynet-EDR.
//!
//! This crate intentionally starts small. Platform sensors, storage, and response
//! actions will build on these stable core types without coupling the initial
//! workspace skeleton to privileged OS APIs or optional dependencies.

/// Operator-facing Skynet-EDR runtime mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Passive detection mode: observe and alert, but do not block.
    Passive,
    /// Guard mode: allow selected high-confidence actions to require approval.
    Guard,
    /// Enforcement mode: allow high-confidence containment actions.
    Enforcement,
}

impl RunMode {
    /// Return the stable lowercase label used in CLI output and configuration.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Guard => "guard",
            Self::Enforcement => "enforcement",
        }
    }
}

/// Static product metadata shared by the CLI, daemon, and future API surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductInfo {
    /// Human-readable product name.
    pub name: &'static str,
    /// Canonical binary name.
    pub binary_name: &'static str,
    /// Default runtime mode for a fresh installation.
    pub run_mode: RunMode,
}

impl Default for ProductInfo {
    fn default() -> Self {
        Self {
            name: "Skynet-EDR",
            binary_name: "skynet-edr",
            run_mode: RunMode::Passive,
        }
    }
}
