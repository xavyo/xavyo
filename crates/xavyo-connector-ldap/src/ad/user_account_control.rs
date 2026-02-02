//! Active Directory userAccountControl bitfield parsing and building.
//!
//! AD stores account state as a bitmask in the `userAccountControl` attribute.
//! This module provides constants, parsing, and builder functions for UAC flags.
//!
//! Reference: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate>

/// Logon script is executed.
pub const SCRIPT: u32 = 0x0001;

/// The user account is disabled.
pub const ACCOUNTDISABLE: u32 = 0x0002;

/// The home directory is required.
pub const HOMEDIR_REQUIRED: u32 = 0x0008;

/// The account is currently locked out.
pub const LOCKOUT: u32 = 0x0010;

/// No password is required.
pub const PASSWD_NOTREQD: u32 = 0x0020;

/// The user cannot change the password.
pub const PASSWD_CANT_CHANGE: u32 = 0x0040;

/// The user can send an encrypted password.
pub const ENCRYPTED_TEXT_PASSWORD_ALLOWED: u32 = 0x0080;

/// This is a default account type that represents a typical user.
pub const NORMAL_ACCOUNT: u32 = 0x0200;

/// This is a computer account for a computer that is a member of this domain.
pub const WORKSTATION_TRUST_ACCOUNT: u32 = 0x1000;

/// This is a computer account for a system backup domain controller.
pub const SERVER_TRUST_ACCOUNT: u32 = 0x2000;

/// The password for this account will never expire.
pub const DONT_EXPIRE_PASSWORD: u32 = 0x10000;

/// This is an MNS logon account.
pub const MNS_LOGON_ACCOUNT: u32 = 0x20000;

/// The user must log on using a smart card.
pub const SMARTCARD_REQUIRED: u32 = 0x40000;

/// The service account is trusted for Kerberos delegation.
pub const TRUSTED_FOR_DELEGATION: u32 = 0x80000;

/// The security context of the user will not be delegated.
pub const NOT_DELEGATED: u32 = 0x100000;

/// Restrict this principal to use only DES encryption types for keys.
pub const USE_DES_KEY_ONLY: u32 = 0x200000;

/// This account does not require Kerberos preauthentication for logon.
pub const DONT_REQUIRE_PREAUTH: u32 = 0x400000;

/// The user password has expired.
pub const PASSWORD_EXPIRED: u32 = 0x800000;

/// The account is enabled for delegation.
pub const TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: u32 = 0x1000000;

/// Parsed representation of the userAccountControl attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAccountControl {
    /// The raw UAC bitmask value.
    pub value: u32,
}

impl UserAccountControl {
    /// Parse a UAC value from the raw integer.
    pub fn from_value(value: u32) -> Self {
        Self { value }
    }

    /// Build a new UAC value starting from zero.
    pub fn new() -> Self {
        Self { value: 0 }
    }

    /// Build a default UAC for a new normal user account.
    pub fn normal_account() -> Self {
        Self {
            value: NORMAL_ACCOUNT,
        }
    }

    /// Check if a specific flag is set.
    pub fn has_flag(&self, flag: u32) -> bool {
        self.value & flag != 0
    }

    /// Set a flag.
    pub fn set_flag(mut self, flag: u32) -> Self {
        self.value |= flag;
        self
    }

    /// Clear a flag.
    pub fn clear_flag(mut self, flag: u32) -> Self {
        self.value &= !flag;
        self
    }

    /// Returns `true` if the account is disabled (ACCOUNTDISABLE bit is set).
    pub fn is_disabled(&self) -> bool {
        self.has_flag(ACCOUNTDISABLE)
    }

    /// Returns `true` if the account is locked out (LOCKOUT bit is set).
    pub fn is_locked(&self) -> bool {
        self.has_flag(LOCKOUT)
    }

    /// Returns `true` if this is a normal user account.
    pub fn is_normal_account(&self) -> bool {
        self.has_flag(NORMAL_ACCOUNT)
    }

    /// Returns `true` if the password never expires.
    pub fn password_never_expires(&self) -> bool {
        self.has_flag(DONT_EXPIRE_PASSWORD)
    }

    /// Returns `true` if a password is not required.
    pub fn password_not_required(&self) -> bool {
        self.has_flag(PASSWD_NOTREQD)
    }

    /// Returns `true` if the password has expired.
    pub fn password_expired(&self) -> bool {
        self.has_flag(PASSWORD_EXPIRED)
    }

    /// Returns `true` if smart card is required for logon.
    pub fn smartcard_required(&self) -> bool {
        self.has_flag(SMARTCARD_REQUIRED)
    }

    /// Determine the `is_active` status for the platform.
    ///
    /// An account is active if it is NOT disabled.
    pub fn is_active(&self) -> bool {
        !self.is_disabled()
    }

    /// Disable the account by setting the ACCOUNTDISABLE flag.
    pub fn disable(self) -> Self {
        self.set_flag(ACCOUNTDISABLE)
    }

    /// Enable the account by clearing the ACCOUNTDISABLE flag.
    pub fn enable(self) -> Self {
        self.clear_flag(ACCOUNTDISABLE)
    }
}

impl Default for UserAccountControl {
    fn default() -> Self {
        Self::new()
    }
}

impl From<u32> for UserAccountControl {
    fn from(value: u32) -> Self {
        Self::from_value(value)
    }
}

impl From<UserAccountControl> for u32 {
    fn from(uac: UserAccountControl) -> Self {
        uac.value
    }
}

impl std::fmt::Display for UserAccountControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UAC(0x{:X})", self.value)?;
        let mut flags = Vec::new();
        if self.is_disabled() {
            flags.push("DISABLED");
        }
        if self.is_locked() {
            flags.push("LOCKED");
        }
        if self.is_normal_account() {
            flags.push("NORMAL");
        }
        if self.password_never_expires() {
            flags.push("PWD_NEVER_EXPIRES");
        }
        if self.password_not_required() {
            flags.push("PWD_NOT_REQUIRED");
        }
        if !flags.is_empty() {
            write!(f, " [{}]", flags.join(", "))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_account() {
        let uac = UserAccountControl::normal_account();
        assert!(uac.is_normal_account());
        assert!(!uac.is_disabled());
        assert!(!uac.is_locked());
        assert!(uac.is_active());
        assert_eq!(uac.value, 0x200);
    }

    #[test]
    fn test_disabled_account() {
        let uac = UserAccountControl::from_value(NORMAL_ACCOUNT | ACCOUNTDISABLE);
        assert!(uac.is_disabled());
        assert!(!uac.is_active());
        assert!(uac.is_normal_account());
        assert_eq!(uac.value, 0x202);
    }

    #[test]
    fn test_locked_account() {
        let uac = UserAccountControl::from_value(NORMAL_ACCOUNT | LOCKOUT);
        assert!(uac.is_locked());
        assert!(uac.is_active()); // locked != disabled
        assert!(uac.is_normal_account());
    }

    #[test]
    fn test_disabled_and_locked() {
        let uac = UserAccountControl::from_value(NORMAL_ACCOUNT | ACCOUNTDISABLE | LOCKOUT);
        assert!(uac.is_disabled());
        assert!(uac.is_locked());
        assert!(!uac.is_active());
    }

    #[test]
    fn test_set_and_clear_flag() {
        let uac = UserAccountControl::normal_account();
        assert!(!uac.is_disabled());

        let disabled = uac.set_flag(ACCOUNTDISABLE);
        assert!(disabled.is_disabled());

        let enabled = disabled.clear_flag(ACCOUNTDISABLE);
        assert!(!enabled.is_disabled());
        assert_eq!(enabled.value, NORMAL_ACCOUNT);
    }

    #[test]
    fn test_disable_enable_helpers() {
        let uac = UserAccountControl::normal_account();

        let disabled = uac.disable();
        assert!(disabled.is_disabled());
        assert_eq!(disabled.value, NORMAL_ACCOUNT | ACCOUNTDISABLE);

        let re_enabled = disabled.enable();
        assert!(!re_enabled.is_disabled());
        assert_eq!(re_enabled.value, NORMAL_ACCOUNT);
    }

    #[test]
    fn test_password_flags() {
        let uac =
            UserAccountControl::from_value(NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD | PASSWD_NOTREQD);
        assert!(uac.password_never_expires());
        assert!(uac.password_not_required());
        assert!(!uac.password_expired());
    }

    #[test]
    fn test_password_expired() {
        let uac = UserAccountControl::from_value(NORMAL_ACCOUNT | PASSWORD_EXPIRED);
        assert!(uac.password_expired());
        assert!(!uac.password_never_expires());
    }

    #[test]
    fn test_smartcard_required() {
        let uac = UserAccountControl::from_value(NORMAL_ACCOUNT | SMARTCARD_REQUIRED);
        assert!(uac.smartcard_required());
    }

    #[test]
    fn test_zero_value() {
        let uac = UserAccountControl::from_value(0);
        assert!(!uac.is_disabled());
        assert!(!uac.is_locked());
        assert!(!uac.is_normal_account());
        assert!(uac.is_active());
        assert_eq!(uac.value, 0);
    }

    #[test]
    fn test_max_u32_value() {
        let uac = UserAccountControl::from_value(u32::MAX);
        assert!(uac.is_disabled());
        assert!(uac.is_locked());
        assert!(uac.is_normal_account());
        assert!(uac.password_never_expires());
        assert!(uac.password_not_required());
        assert!(uac.password_expired());
        assert!(uac.smartcard_required());
    }

    #[test]
    fn test_typical_active_user() {
        // Typical AD user: normal account + password never expires
        let uac = UserAccountControl::from_value(0x10200);
        assert!(uac.is_normal_account());
        assert!(uac.password_never_expires());
        assert!(!uac.is_disabled());
        assert!(uac.is_active());
    }

    #[test]
    fn test_typical_disabled_user() {
        // Disabled user in AD: normal + disabled
        let uac = UserAccountControl::from_value(0x10202);
        assert!(uac.is_normal_account());
        assert!(uac.is_disabled());
        assert!(uac.password_never_expires());
        assert!(!uac.is_active());
    }

    #[test]
    fn test_from_u32_conversion() {
        let uac: UserAccountControl = 0x200u32.into();
        assert!(uac.is_normal_account());
    }

    #[test]
    fn test_into_u32_conversion() {
        let uac = UserAccountControl::normal_account().disable();
        let val: u32 = uac.into();
        assert_eq!(val, 0x202);
    }

    #[test]
    fn test_builder_chaining() {
        let uac = UserAccountControl::new()
            .set_flag(NORMAL_ACCOUNT)
            .set_flag(DONT_EXPIRE_PASSWORD);
        assert!(uac.is_normal_account());
        assert!(uac.password_never_expires());
        assert!(!uac.is_disabled());
    }

    #[test]
    fn test_display() {
        let uac = UserAccountControl::from_value(NORMAL_ACCOUNT | ACCOUNTDISABLE);
        let display = format!("{}", uac);
        assert!(display.contains("DISABLED"));
        assert!(display.contains("NORMAL"));
        assert!(display.contains("0x202"));
    }

    #[test]
    fn test_default() {
        let uac = UserAccountControl::default();
        assert_eq!(uac.value, 0);
    }
}
