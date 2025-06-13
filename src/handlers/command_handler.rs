//! Policy command handler implementation

use crate::{Policy, commands::*};
use cim_core_domain::command::CommandHandler;
use cim_core_domain::repository::AggregateRepository;
use async_trait::async_trait;

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

#[async_trait]
impl<R: AggregateRepository<Policy> + Send + Sync> CommandHandler<EnactPolicy> for PolicyCommandHandler<R> {
    type Error = cim_core_domain::errors::DomainError;

    async fn handle(&self, command: EnactPolicy) -> Result<(), Self::Error> {
        let mut policy = Policy::new(
            command.policy_id,
            command.policy_type,
            command.scope,
            command.owner_id,
        );

        // Add metadata component
        policy.add_component(command.metadata)?;

        self.repository.save(&policy).await?;
        Ok(())
    }
}

// Additional command handlers would be implemented similarly...
