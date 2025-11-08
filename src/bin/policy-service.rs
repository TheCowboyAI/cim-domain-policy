//! Policy Service - NATS-enabled service for policy domain
//!
//! This service provides NATS request/reply handlers for all policy operations,
//! integrating with JetStream for durable event sourcing.
//!
//! ## Environment Variables
//!
//! - `NATS_URL` - NATS server URL (default: nats://localhost:4222)
//! - `STREAM_NAME` - JetStream stream name (default: POLICY_EVENTS)
//! - `LOG_LEVEL` - Logging level (default: info)
//! - `SNAPSHOT_FREQUENCY` - Events between snapshots (default: 100)
//!
//! ## NATS Subjects
//!
//! Commands (request/reply):
//! - `policy.commands.create` - Create new policy
//! - `policy.commands.update` - Update policy
//! - `policy.commands.approve` - Approve policy
//! - `policy.commands.activate` - Activate policy
//! - `policy.commands.suspend` - Suspend policy
//! - `policy.commands.revoke` - Revoke policy
//! - `policy.commands.archive` - Archive policy
//! - `policy.commands.create_set` - Create policy set
//! - `policy.commands.add_to_set` - Add policy to set
//! - `policy.commands.remove_from_set` - Remove policy from set
//! - `policy.commands.grant_exemption` - Grant exemption
//! - `policy.commands.revoke_exemption` - Revoke exemption
//! - `policy.commands.evaluate` - Evaluate policy
//! - `policy.commands.check_compliance` - Check compliance
//!
//! Events (publish):
//! - `events.policy.{policy_id}.{event_type}` - Policy domain events

use cim_domain_policy::adapters::NatsEventPublisher;
use cim_domain_policy::infrastructure::{
    ExemptionRepository, NatsEventStore, PolicyRepository, PolicySetRepository,
};
use cim_domain_policy::ports::EventPublisher;
use futures::StreamExt;
use std::env;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let stream_name = env::var("STREAM_NAME").unwrap_or_else(|_| "POLICY_EVENTS".to_string());
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let snapshot_frequency: u64 = env::var("SNAPSHOT_FREQUENCY")
        .unwrap_or_else(|_| "100".to_string())
        .parse()
        .unwrap_or(100);

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(match log_level.as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        })
        .init();

    info!("Starting Policy Service");
    info!("NATS URL: {}", nats_url);
    info!("Stream: {}", stream_name);
    info!("Log Level: {}", log_level);
    info!("Snapshot Frequency: {}", snapshot_frequency);

    // Connect to NATS
    info!("Connecting to NATS...");
    let client = async_nats::connect(&nats_url).await?;
    info!("Connected to NATS");

    // Create JetStream context
    let jetstream = async_nats::jetstream::new(client.clone());

    // Create event store
    info!("Initializing event store...");
    let event_store = Arc::new(NatsEventStore::new(jetstream.clone(), stream_name.clone()).await?);
    info!("Event store initialized");

    // Create repositories
    let policy_repo = Arc::new(
        PolicyRepository::new(event_store.clone()).with_snapshot_frequency(snapshot_frequency),
    );
    let policy_set_repo = Arc::new(
        PolicySetRepository::new(event_store.clone()).with_snapshot_frequency(snapshot_frequency),
    );
    let exemption_repo = Arc::new(
        ExemptionRepository::new(event_store.clone()).with_snapshot_frequency(snapshot_frequency),
    );

    // Create event publisher
    let publisher = Arc::new(NatsEventPublisher::new(jetstream.clone(), stream_name.clone()));

    // Subscribe to command subjects
    info!("Subscribing to command subjects...");

    // Policy commands
    let mut create_sub = client.subscribe("policy.commands.create").await?;
    let mut update_sub = client.subscribe("policy.commands.update").await?;
    let mut approve_sub = client.subscribe("policy.commands.approve").await?;
    let mut activate_sub = client.subscribe("policy.commands.activate").await?;
    let mut suspend_sub = client.subscribe("policy.commands.suspend").await?;
    let mut revoke_sub = client.subscribe("policy.commands.revoke").await?;
    let mut archive_sub = client.subscribe("policy.commands.archive").await?;

    // PolicySet commands
    let mut create_set_sub = client.subscribe("policy.commands.create_set").await?;
    let mut add_to_set_sub = client.subscribe("policy.commands.add_to_set").await?;
    let mut remove_from_set_sub = client.subscribe("policy.commands.remove_from_set").await?;

    // Exemption commands
    let mut grant_exemption_sub = client.subscribe("policy.commands.grant_exemption").await?;
    let mut revoke_exemption_sub = client.subscribe("policy.commands.revoke_exemption").await?;

    // Evaluation commands
    let mut evaluate_sub = client.subscribe("policy.commands.evaluate").await?;
    let mut check_compliance_sub = client.subscribe("policy.commands.check_compliance").await?;

    info!("Subscribed to all command subjects");

    // Spawn handler tasks
    info!("Starting command handlers...");

    // Policy command handlers
    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = create_sub.next().await {
                handle_create_policy(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = update_sub.next().await {
                handle_update_policy(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = approve_sub.next().await {
                handle_approve_policy(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = activate_sub.next().await {
                handle_activate_policy(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = suspend_sub.next().await {
                handle_suspend_policy(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = revoke_sub.next().await {
                handle_revoke_policy(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = archive_sub.next().await {
                handle_archive_policy(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    // PolicySet command handlers
    {
        let repo = policy_set_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = create_set_sub.next().await {
                handle_create_set(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_set_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = add_to_set_sub.next().await {
                handle_add_to_set(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_set_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = remove_from_set_sub.next().await {
                handle_remove_from_set(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    // Exemption command handlers
    {
        let repo = exemption_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = grant_exemption_sub.next().await {
                handle_grant_exemption(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = exemption_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = revoke_exemption_sub.next().await {
                handle_revoke_exemption(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    // Evaluation command handlers
    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = evaluate_sub.next().await {
                handle_evaluate(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    {
        let repo = policy_repo.clone();
        let pub_ref = publisher.clone();
        let client_ref = client.clone();
        tokio::spawn(async move {
            while let Some(msg) = check_compliance_sub.next().await {
                handle_check_compliance(msg, repo.clone(), pub_ref.clone(), client_ref.clone()).await;
            }
        });
    }

    info!("Policy Service is ready");

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Shutting down Policy Service...");

    Ok(())
}

// ============================================================================
// Command Handlers (Skeleton Implementations)
// ============================================================================

async fn handle_create_policy(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received create policy command");

    // TODO: Deserialize command from msg.payload
    // TODO: Create policy aggregate
    // TODO: Generate PolicyCreated event
    // TODO: Save event via repository
    // TODO: Publish event

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Policy creation command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_update_policy(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received update policy command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Policy update command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_approve_policy(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received approve policy command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Policy approval command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_activate_policy(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received activate policy command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Policy activation command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_suspend_policy(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received suspend policy command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Policy suspension command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_revoke_policy(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received revoke policy command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Policy revocation command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_archive_policy(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received archive policy command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Policy archival command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_create_set(
    msg: async_nats::Message,
    _repository: Arc<PolicySetRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received create policy set command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "PolicySet creation command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_add_to_set(
    msg: async_nats::Message,
    _repository: Arc<PolicySetRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received add to set command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Add to set command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_remove_from_set(
    msg: async_nats::Message,
    _repository: Arc<PolicySetRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received remove from set command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Remove from set command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_grant_exemption(
    msg: async_nats::Message,
    _repository: Arc<ExemptionRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received grant exemption command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Exemption grant command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_revoke_exemption(
    msg: async_nats::Message,
    _repository: Arc<ExemptionRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received revoke exemption command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Exemption revocation command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_evaluate(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received policy evaluation command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Policy evaluation command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}

async fn handle_check_compliance(
    msg: async_nats::Message,
    _repository: Arc<PolicyRepository>,
    _publisher: Arc<NatsEventPublisher>,
    client: async_nats::Client,
) {
    info!("Received compliance check command");

    if let Some(reply) = msg.reply {
        let response = serde_json::json!({
            "status": "accepted",
            "message": "Compliance check command received (implementation pending)"
        });
        let payload = serde_json::to_vec(&response).unwrap();
        let _ = client.publish(reply, payload.into()).await;
    }
}
