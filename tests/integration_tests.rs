//! Integration tests for policy domain - all workflows in one file
//! 
//! Tests pure functional event sourcing across all 3 aggregates:
//! - Policy lifecycle
//! - PolicySet management  
//! - PolicyExemption workflows

use cim_domain_policy::aggregate::*;
use cim_domain_policy::events::*;
use cim_domain_policy::value_objects::*;
use chrono::{Duration, Utc};
use uuid::Uuid;

fn msg_id() -> cim_domain::MessageIdentity {
    let id = Uuid::now_v7();
    cim_domain::MessageIdentity {
        correlation_id: cim_domain::CorrelationId::Single(id),
        causation_id: cim_domain::CausationId(id),
        message_id: id,
    }
}

#[test]
fn test_policy_complete_lifecycle() {
    let pid = PolicyId::new();
    let mut p = Policy::new("Test", "Description");
    
    // Created
    p = p.apply_event_pure(&PolicyEvent::PolicyCreated(PolicyCreated {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        name: "Test".to_string(), description: "Description".to_string(),
        policy_type: "Security".to_string(), created_by: "admin".to_string(),
        created_at: Utc::now(),
    })).unwrap();
    assert_eq!(p.status, PolicyStatus::Draft);
    
    // Approved
    p = p.apply_event_pure(&PolicyEvent::PolicyApproved(PolicyApproved {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        approved_by: "manager".to_string(), approved_at: Utc::now(),
        approval_notes: None,
    })).unwrap();
    assert_eq!(p.status, PolicyStatus::Approved);
    
    // Activated
    p = p.apply_event_pure(&PolicyEvent::PolicyActivated(PolicyActivated {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        activated_by: "admin".to_string(), activated_at: Utc::now(),
        effective_from: Utc::now(), effective_until: None,
    })).unwrap();
    assert_eq!(p.status, PolicyStatus::Active);
    
    // Suspended
    p = p.apply_event_pure(&PolicyEvent::PolicySuspended(PolicySuspended {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        suspended_by: "admin".to_string(), suspended_at: Utc::now(),
        reason: "Maintenance".to_string(), expected_resume_date: None,
    })).unwrap();
    assert_eq!(p.status, PolicyStatus::Suspended);
    
    // Revoked
    p = p.apply_event_pure(&PolicyEvent::PolicyRevoked(PolicyRevoked {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        revoked_by: "admin".to_string(), revoked_at: Utc::now(),
        reason: "Superseded".to_string(), immediate: true,
    })).unwrap();
    assert_eq!(p.status, PolicyStatus::Revoked);
    
    // Archived
    p = p.apply_event_pure(&PolicyEvent::PolicyArchived(PolicyArchived {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        archived_by: "admin".to_string(), archived_at: Utc::now(),
        retention_period_days: Some(365),
    })).unwrap();
    assert_eq!(p.status, PolicyStatus::Archived);
}

#[test]
fn test_policy_set_workflows() {
    let sid = PolicySetId::new();
    let mut ps = PolicySet::new("Test Set", "Description");
    
    // Created
    ps = ps.apply_event_pure(&PolicyEvent::PolicySetCreated(PolicySetCreated {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_set_id: sid.clone(),
        name: "Test Set".to_string(), description: "Description".to_string(),
        created_by: "admin".to_string(), created_at: Utc::now(),
    })).unwrap();
    assert_eq!(ps.policies.len(), 0);
    
    // Add policies
    let p1 = PolicyId::new();
    let p2 = PolicyId::new();
    
    ps = ps.apply_event_pure(&PolicyEvent::PolicyAddedToSet(PolicyAddedToSet {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_set_id: sid.clone(),
        policy_id: p1.clone(), added_by: "admin".to_string(), added_at: Utc::now(),
    })).unwrap();
    assert_eq!(ps.policies.len(), 1);
    
    ps = ps.apply_event_pure(&PolicyEvent::PolicyAddedToSet(PolicyAddedToSet {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_set_id: sid.clone(),
        policy_id: p2.clone(), added_by: "admin".to_string(), added_at: Utc::now(),
    })).unwrap();
    assert_eq!(ps.policies.len(), 2);
    
    // Remove policy
    ps = ps.apply_event_pure(&PolicyEvent::PolicyRemovedFromSet(PolicyRemovedFromSet {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_set_id: sid.clone(),
        policy_id: p1.clone(), removed_by: "admin".to_string(), removed_at: Utc::now(),
        reason: Some("No longer needed".to_string()),
    })).unwrap();
    assert_eq!(ps.policies.len(), 1);
    assert!(ps.policies.contains(&p2));
}

#[test]
fn test_exemption_workflows() {
    let eid = ExemptionId::new();
    let pid = PolicyId::new();
    let mut ex = PolicyExemption::new(
        pid.clone(), "Test", "Justification", "admin",
        Utc::now() + Duration::days(30),
    );
    
    // Granted
    ex = ex.apply_event_pure(&PolicyEvent::PolicyExemptionGranted(PolicyExemptionGranted {
        event_id: Uuid::now_v7(), identity: msg_id(), exemption_id: eid.clone(),
        policy_id: pid.clone(), granted_by: "admin".to_string(), granted_at: Utc::now(),
        reason: "Test".to_string(), valid_until: Utc::now() + Duration::days(30),
        risk_acceptance: None,
    })).unwrap();
    assert_eq!(ex.status, ExemptionStatus::Active);
    
    // Revoked
    ex = ex.apply_event_pure(&PolicyEvent::PolicyExemptionRevoked(PolicyExemptionRevoked {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        exemption_id: eid.clone(), revoked_by: "admin".to_string(), revoked_at: Utc::now(),
        reason: "No longer needed".to_string(),
    })).unwrap();
    assert!(matches!(ex.status, ExemptionStatus::Revoked { .. }));
}

#[test]
fn test_exemption_expiration() {
    let eid = ExemptionId::new();
    let pid = PolicyId::new();
    let mut ex = PolicyExemption::new(
        pid.clone(), "Test", "Justification", "admin",
        Utc::now() + Duration::days(7),
    );
    
    ex = ex.apply_event_pure(&PolicyEvent::PolicyExemptionGranted(PolicyExemptionGranted {
        event_id: Uuid::now_v7(), identity: msg_id(), exemption_id: eid.clone(),
        policy_id: pid.clone(), granted_by: "admin".to_string(), granted_at: Utc::now(),
        reason: "Test".to_string(), valid_until: Utc::now() + Duration::days(7),
        risk_acceptance: None,
    })).unwrap();
    
    // Expired
    ex = ex.apply_event_pure(&PolicyEvent::PolicyExemptionExpired(PolicyExemptionExpired {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        exemption_id: eid.clone(), expired_at: Utc::now(),
    })).unwrap();
    assert_eq!(ex.status, ExemptionStatus::Expired);
}

#[test]
fn test_pure_functions_immutability() {
    let pid = PolicyId::new();
    let orig = Policy::new("Original", "Original Description");
    
    let new_p = orig.apply_event_pure(&PolicyEvent::PolicyCreated(PolicyCreated {
        event_id: Uuid::now_v7(), identity: msg_id(), policy_id: pid.clone(),
        name: "Changed".to_string(), description: "Changed Description".to_string(),
        policy_type: "Security".to_string(), created_by: "admin".to_string(),
        created_at: Utc::now(),
    })).unwrap();
    
    // Original unchanged
    assert_eq!(orig.name, "Original");
    // New changed
    assert_eq!(new_p.name, "Changed");
}
