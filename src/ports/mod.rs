//! Ports - interfaces for external integrations (hexagonal architecture)

pub mod event_publisher;

pub use event_publisher::{EventPublisher, PublishError, QueryError, event_to_subject};
