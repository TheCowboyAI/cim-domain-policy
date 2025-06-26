//! Metadata component for policy domain
//!
//! Provides human-readable information and categorization for policies

use bevy_ecs::component::Component;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use chrono::{DateTime, Utc};
use bevy_ecs::prelude::*;
use std::collections::HashMap;
use uuid::Uuid;

/// Policy metadata component
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadataComponent {
    /// Human-readable name
    pub name: String,
    
    /// Description of the policy
    pub description: String,
    
    /// Policy category/tags
    pub tags: HashSet<String>,
    
    /// Effective date
    pub effective_date: Option<DateTime<Utc>>,
    
    /// Expiration date
    pub expiration_date: Option<DateTime<Utc>>,
    
    /// Compliance frameworks this policy supports
    pub compliance_frameworks: HashSet<String>,
    
    /// Component metadata
    pub metadata: ComponentMetadata,
}

/// Component metadata for tracking creation and modification
#[derive(Component, Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentMetadata {
    /// Entity type identifier
    pub entity_type: String,
    
    /// When the component was created
    pub created_at: DateTime<Utc>,
    
    /// When the component was last updated
    pub updated_at: DateTime<Utc>,
    
    /// Version number for optimistic locking
    pub version: u64,
    
    /// Additional metadata as key-value pairs
    pub properties: HashMap<String, String>,
}

impl PolicyMetadataComponent {
    /// Create new policy metadata
    pub fn new(name: String, description: String) -> Self {
        Self {
            name,
            description,
            tags: HashSet::new(),
            effective_date: None,
            expiration_date: None,
            compliance_frameworks: HashSet::new(),
            metadata: ComponentMetadata {
                entity_type: "PolicyMetadataComponent".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 1,
                properties: HashMap::new(),
            },
        }
    }
    
    /// Add a tag
    pub fn add_tag(&mut self, tag: String) {
        self.tags.insert(tag);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Add multiple tags
    pub fn add_tags(&mut self, tags: impl IntoIterator<Item = String>) {
        for tag in tags {
            self.tags.insert(tag);
        }
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Remove a tag
    pub fn remove_tag(&mut self, tag: &str) -> bool {
        let removed = self.tags.remove(tag);
        if removed {
            self.metadata.updated_at = Utc::now();
            self.metadata.version += 1;
        }
        removed
    }
    
    /// Set effective date
    pub fn set_effective_date(&mut self, date: DateTime<Utc>) {
        self.effective_date = Some(date);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Set expiration date
    pub fn set_expiration_date(&mut self, date: DateTime<Utc>) {
        self.expiration_date = Some(date);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Add compliance framework
    pub fn add_compliance_framework(&mut self, framework: String) {
        self.compliance_frameworks.insert(framework);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Check if policy is currently effective
    pub fn is_effective(&self) -> bool {
        let now = Utc::now();
        
        // Check if we're past the effective date
        if let Some(effective) = self.effective_date {
            if now < effective {
                return false;
            }
        }
        
        // Check if we're before the expiration date
        if let Some(expiration) = self.expiration_date {
            if now > expiration {
                return false;
            }
        }
        
        true
    }
    
    /// Update name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Update description
    pub fn set_description(&mut self, description: String) {
        self.description = description;
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
}

impl Default for PolicyMetadataComponent {
    fn default() -> Self {
        Self::new(
            "Unnamed Policy".to_string(),
            "No description provided".to_string()
        )
    }
}

impl ComponentMetadata {
    /// Create new metadata with the given entity type
    pub fn new(entity_type: String) -> Self {
        let now = Utc::now();
        Self {
            entity_type,
            created_at: now,
            updated_at: now,
            version: 1,
            properties: HashMap::new(),
        }
    }
    
    /// Update the metadata for a modification
    pub fn update(&mut self) {
        self.updated_at = Utc::now();
        self.version += 1;
    }
    
    /// Add a metadata key-value pair
    pub fn add_property(&mut self, key: String, value: String) {
        self.properties.insert(key, value);
        self.update();
    }
    
    /// Get a metadata value by key
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.properties.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    
    #[test]
    fn test_create_metadata() {
        let metadata = PolicyMetadataComponent::new(
            "Test Policy".to_string(),
            "A test policy for unit tests".to_string()
        );
        
        assert_eq!(metadata.name, "Test Policy");
        assert_eq!(metadata.description, "A test policy for unit tests");
        assert!(metadata.tags.is_empty());
        assert!(metadata.compliance_frameworks.is_empty());
    }
    
    #[test]
    fn test_tags() {
        let mut metadata = PolicyMetadataComponent::default();
        
        metadata.add_tag("security".to_string());
        metadata.add_tag("compliance".to_string());
        metadata.add_tags(vec!["gdpr".to_string(), "hipaa".to_string()]);
        
        assert_eq!(metadata.tags.len(), 4);
        assert!(metadata.tags.contains("security"));
        assert!(metadata.tags.contains("gdpr"));
        
        assert!(metadata.remove_tag("security"));
        assert!(!metadata.tags.contains("security"));
        assert_eq!(metadata.tags.len(), 3);
    }
    
    #[test]
    fn test_effectiveness() {
        let mut metadata = PolicyMetadataComponent::default();
        
        // No dates set - should be effective
        assert!(metadata.is_effective());
        
        // Set future effective date
        let future = Utc::now() + Duration::days(1);
        metadata.set_effective_date(future);
        assert!(!metadata.is_effective());
        
        // Set past effective date
        let past = Utc::now() - Duration::days(1);
        metadata.set_effective_date(past);
        assert!(metadata.is_effective());
        
        // Set past expiration date
        metadata.set_expiration_date(past);
        assert!(!metadata.is_effective());
        
        // Set future expiration date
        metadata.set_expiration_date(future);
        assert!(metadata.is_effective());
    }
    
    #[test]
    fn test_compliance_frameworks() {
        let mut metadata = PolicyMetadataComponent::default();
        
        metadata.add_compliance_framework("SOC2".to_string());
        metadata.add_compliance_framework("ISO27001".to_string());
        metadata.add_compliance_framework("PCI-DSS".to_string());
        
        assert_eq!(metadata.compliance_frameworks.len(), 3);
        assert!(metadata.compliance_frameworks.contains("SOC2"));
        assert!(metadata.compliance_frameworks.contains("ISO27001"));
        assert!(metadata.compliance_frameworks.contains("PCI-DSS"));
    }
} 