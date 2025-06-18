//! Policy command handler implementation

use crate::{Policy, commands::*};
use cim_domain::{CommandHandler, CommandEnvelope, CommandAcknowledgment, CommandStatus};
use cim_domain::AggregateRepository;

/// Policy command handler
pub struct PolicyCommandHandler<R: AggregateRepository<Policy>> {
    repository: R,
}

impl<R: AggregateRepository<Policy>> PolicyCommandHandler<R> {
    /// Create a new policy command handler
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
}

impl<R: AggregateRepository<Policy> + Send + Sync> CommandHandler<EnactPolicy> for PolicyCommandHandler<R> {
    fn handle(&mut self, envelope: CommandEnvelope<EnactPolicy>) -> CommandAcknowledgment {
        let command = envelope.command;

        let mut policy = Policy::new(
            command.policy_id,
            command.policy_type,
            command.scope,
            command.owner_id,
        );

        // Add metadata component
        match policy.add_component(command.metadata) {
            Ok(_) => {
                // Save the policy to the repository
                match self.repository.save(&policy) {
                    Ok(_) => {
                        CommandAcknowledgment {
                            command_id: envelope.id,
                            correlation_id: envelope.correlation_id,
                            status: CommandStatus::Accepted,
                            reason: None,
                        }
                    }
                    Err(e) => {
                        CommandAcknowledgment {
                            command_id: envelope.id,
                            correlation_id: envelope.correlation_id,
                            status: CommandStatus::Rejected,
                            reason: Some(format!("Failed to save policy: {e}")),
                        }
                    }
                }
            }
            Err(e) => {
                CommandAcknowledgment {
                    command_id: envelope.id,
                    correlation_id: envelope.correlation_id,
                    status: CommandStatus::Rejected,
                    reason: Some(e.to_string()),
                }
            }
        }
    }
}

// Additional command handlers would be implemented similarly...
