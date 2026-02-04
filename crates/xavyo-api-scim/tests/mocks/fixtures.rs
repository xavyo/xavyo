//! Test user and group fixtures for mock clients.

use uuid::Uuid;

/// Test user fixture for interoperability tests.
#[derive(Debug, Clone)]
pub struct TestUser {
    /// User email (userName in SCIM).
    pub email: String,
    /// External ID from `IdP`.
    pub external_id: String,
    /// Given name.
    pub first_name: String,
    /// Family name.
    pub last_name: String,
    /// Display name (optional).
    pub display_name: Option<String>,
    /// Active status.
    pub active: bool,
}

impl TestUser {
    /// Create a new test user with generated values.
    pub fn generate() -> Self {
        let id = Uuid::new_v4();
        Self {
            email: format!("test-{id}@example.com"),
            external_id: id.to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            display_name: Some("Test User".to_string()),
            active: true,
        }
    }

    /// Create a test user with specific email.
    pub fn with_email(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            external_id: Uuid::new_v4().to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            display_name: Some("Test User".to_string()),
            active: true,
        }
    }

    /// Create an inactive test user.
    pub fn inactive() -> Self {
        let mut user = Self::generate();
        user.active = false;
        user
    }
}

/// Test group fixture for interoperability tests.
#[derive(Debug, Clone)]
pub struct TestGroup {
    /// Group display name.
    pub display_name: String,
    /// External ID from `IdP`.
    pub external_id: String,
    /// Member user IDs.
    pub members: Vec<String>,
}

impl TestGroup {
    /// Create a new test group with generated values.
    pub fn generate() -> Self {
        let id = Uuid::new_v4();
        Self {
            display_name: format!("TestGroup-{}", &id.to_string()[..8]),
            external_id: id.to_string(),
            members: vec![],
        }
    }

    /// Create a test group with specific name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            display_name: name.into(),
            external_id: Uuid::new_v4().to_string(),
            members: vec![],
        }
    }

    /// Add a member to the group.
    pub fn with_member(mut self, member_id: impl Into<String>) -> Self {
        self.members.push(member_id.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_generate_is_unique() {
        let user1 = TestUser::generate();
        let user2 = TestUser::generate();
        assert_ne!(user1.email, user2.email);
        assert_ne!(user1.external_id, user2.external_id);
    }

    #[test]
    fn test_user_with_email() {
        let user = TestUser::with_email("custom@example.com");
        assert_eq!(user.email, "custom@example.com");
    }

    #[test]
    fn test_user_inactive() {
        let user = TestUser::inactive();
        assert!(!user.active);
    }

    #[test]
    fn test_group_generate() {
        let group = TestGroup::generate();
        assert!(group.display_name.starts_with("TestGroup-"));
        assert!(group.members.is_empty());
    }

    #[test]
    fn test_group_with_member() {
        let group = TestGroup::generate().with_member("user-123");
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0], "user-123");
    }
}
