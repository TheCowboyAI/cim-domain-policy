//! ECS systems for policy domain

use bevy_ecs::prelude::*;
use bevy_app::prelude::*;

pub mod approval_workflow;
pub mod authentication;
pub mod enforcement;
pub mod policy_lifecycle;

pub use approval_workflow::*;
pub use authentication::*;
pub use enforcement::*;
pub use policy_lifecycle::*;

use crate::commands::*;
use crate::events::*;

/// Plugin for registering all policy systems
pub struct PolicySystemsPlugin;

impl Plugin for PolicySystemsPlugin {
    fn build(&self, app: &mut App) {
        // Policy lifecycle systems
        app.add_systems(Update, (
            create_policy_system,
            update_policy_status_system,
            archive_policy_system,
        ));
        
        // Approval workflow systems
        app.add_systems(Update, (
            submit_for_approval_system,
            process_approvals_system,
            check_approval_requirements_system,
            handle_external_approvals_system,
        ));
        
        // Enforcement systems
        app.add_systems(Update, (
            enforce_policies_system,
            detect_violations_system,
            take_enforcement_actions_system,
            update_enforcement_metrics_system,
            handle_enforcement_mode_changes_system,
            resolve_violations_system,
        ));
        
        // Authentication systems
        app.add_systems(Update, (
            start_authentication_session,
            process_authentication_input,
            check_session_timeouts,
            update_authentication_status,
            handle_risk_assessment_changes,
        ));
    }
} 