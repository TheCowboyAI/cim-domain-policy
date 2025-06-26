//! Policy Domain
//!
//! The Policy domain handles policy management, enforcement, and compliance
//! within the CIM system. It provides a flexible framework for defining and
//! enforcing various types of policies including access control, data governance,
//! and compliance policies.

// Re-export bevy types for convenience
pub mod bevy {
    pub mod prelude {
        pub use bevy_ecs::prelude::*;
        pub use bevy_app::prelude::*;
        pub use bevy_time::{Time, Timer};
    }
}

// Re-export main types
pub use crate::aggregate::*;
pub use crate::commands::*;
pub use crate::components::*;
pub use crate::events::*;
pub use crate::handlers::*;
pub use crate::projections::*;
pub use crate::queries::*;
pub use crate::value_objects::*;

pub mod aggregate;
pub mod commands;
pub mod components;
pub mod events;
pub mod handlers;
pub mod projections;
pub mod queries;
pub mod systems;
pub mod value_objects;

// Re-export system plugin
pub use systems::PolicySystemsPlugin;

// Re-export specific systems for convenience
pub use systems::{
    policy_lifecycle::create_policy_system,
    policy_lifecycle::update_policy_status_system,
    policy_lifecycle::archive_policy_system,
    
    approval_workflow::submit_for_approval_system,
    approval_workflow::process_approvals_system,
    approval_workflow::check_approval_requirements_system,
    approval_workflow::handle_external_approvals_system,
    
    enforcement::enforce_policies_system,
    enforcement::detect_violations_system,
    enforcement::take_enforcement_actions_system,
    enforcement::update_enforcement_metrics_system,
    enforcement::handle_enforcement_mode_changes_system,
    enforcement::resolve_violations_system,
    
    authentication::start_authentication_session,
    authentication::process_authentication_input,
    authentication::check_session_timeouts,
    authentication::update_authentication_status,
    authentication::handle_risk_assessment_changes,
};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::aggregate::Policy;
    pub use crate::commands::{EnactPolicy, SubmitPolicyForApproval, ArchivePolicy};
    pub use crate::components::{PolicyEntity, PolicyId, ComponentMetadata};
    pub use crate::events::{PolicyEnacted, PolicySubmittedForApproval, PolicyArchived};
    pub use crate::handlers::{EnactPolicyHandler, SubmitPolicyForApprovalHandler};
    pub use crate::value_objects::{PolicyType, PolicyScope, PolicyStatus};
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_policy_id_creation() {
        let id1 = PolicyId(Uuid::new_v4());
        let id2 = PolicyId(Uuid::new_v4());
        assert_ne!(id1, id2);
    }
}
