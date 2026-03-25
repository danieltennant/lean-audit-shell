// Phase 4 — OTel exporter (not yet implemented)
// Compiled only with --features otel, except for the NullExporter
// which is always available.

pub mod exporter;
pub mod shutdown;

/// Trait satisfied by both NullExporter (default) and OtelExporter (--features otel).
/// The record type will be filled in during Phase 3 when AuditRecord is defined.
pub trait LogExporter: Send + Sync {
    fn shutdown(&self);
}

/// No-op exporter used when audit.remote.enabled = false.
pub struct NullExporter;

impl LogExporter for NullExporter {
    fn shutdown(&self) {}
}
