//! Account login utilities for R-Squared blockchain
//!
//! This module provides functionality for account authentication,
//! session management, and secure login operations.

use crate::chain::{
    chain_types::*,
    ObjectId,
};
use crate::ecc::{PrivateKey, PublicKey, Signature, BrainKey};
use crate::error::{ChainError, ChainResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Login session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSession {
    /// Account ID
    pub account_id: ObjectId,
    /// Session token
    pub session_token: String,
    /// Session creation time
    pub created_at: u64,
    /// Session expiration time
    pub expires_at: u64,
    /// Public key used for authentication
    pub public_key: String,
    /// Session metadata
    pub metadata: HashMap<String, String>,
}

/// Login credentials
#[derive(Debug, Clone)]
pub struct LoginCredentials {
    /// Account name or ID
    pub account: String,
    /// Private key for signing
    pub private_key: PrivateKey,
    /// Optional memo key
    pub memo_key: Option<PrivateKey>,
}

/// Login challenge for secure authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginChallenge {
    /// Challenge ID
    pub challenge_id: String,
    /// Random nonce
    pub nonce: String,
    /// Challenge timestamp
    pub timestamp: u64,
    /// Challenge expiration
    pub expires_at: u64,
    /// Required account (if specified)
    pub account_id: Option<ObjectId>,
}

/// Login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    /// Challenge ID
    pub challenge_id: String,
    /// Account ID
    pub account_id: ObjectId,
    /// Signature of the challenge
    pub signature: String,
    /// Public key used for signing
    pub public_key: String,
    /// Response timestamp
    pub timestamp: u64,
}

/// Account login manager
#[derive(Debug)]
pub struct AccountLogin {
    /// Active sessions
    sessions: HashMap<String, LoginSession>,
    /// Active challenges
    challenges: HashMap<String, LoginChallenge>,
    /// Session timeout duration
    session_timeout: Duration,
    /// Challenge timeout duration
    challenge_timeout: Duration,
}

impl AccountLogin {
    /// Create a new account login manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            challenges: HashMap::new(),
            session_timeout: Duration::from_secs(3600), // 1 hour
            challenge_timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new account login manager with custom timeouts
    pub fn with_timeouts(session_timeout: Duration, challenge_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            challenges: HashMap::new(),
            session_timeout,
            challenge_timeout,
        }
    }

    /// Generate login credentials from brain key
    pub fn credentials_from_brain_key(
        brain_key: &str,
        account: &str,
        sequence: u32,
    ) -> ChainResult<LoginCredentials> {
        let brain_key_obj = BrainKey::from_words(brain_key)?;
        let private_key = brain_key_obj.to_private_key()?;
        
        Ok(LoginCredentials {
            account: account.to_string(),
            private_key,
            memo_key: None,
        })
    }

    /// Generate login credentials from WIF private key
    pub fn credentials_from_wif(
        wif: &str,
        account: &str,
    ) -> ChainResult<LoginCredentials> {
        let private_key = PrivateKey::from_wif(wif)?;
        
        Ok(LoginCredentials {
            account: account.to_string(),
            private_key,
            memo_key: None,
        })
    }

    /// Generate login credentials with memo key
    pub fn credentials_with_memo(
        credentials: LoginCredentials,
        memo_wif: &str,
    ) -> ChainResult<LoginCredentials> {
        let memo_key = PrivateKey::from_wif(memo_wif)?;
        
        Ok(LoginCredentials {
            account: credentials.account,
            private_key: credentials.private_key,
            memo_key: Some(memo_key),
        })
    }

    /// Create a login challenge
    pub fn create_challenge(&mut self, account_id: Option<ObjectId>) -> ChainResult<LoginChallenge> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs();

        let challenge_id = self.generate_challenge_id()?;
        let nonce = self.generate_nonce()?;
        
        let challenge = LoginChallenge {
            challenge_id: challenge_id.clone(),
            nonce,
            timestamp: now,
            expires_at: now + self.challenge_timeout.as_secs(),
            account_id,
        };

        self.challenges.insert(challenge_id.clone(), challenge.clone());
        
        // Clean up expired challenges
        self.cleanup_expired_challenges();
        
        Ok(challenge)
    }

    /// Respond to a login challenge
    pub fn respond_to_challenge(
        &self,
        challenge_id: &str,
        credentials: &LoginCredentials,
        account_id: ObjectId,
    ) -> ChainResult<LoginResponse> {
        let challenge = self.challenges.get(challenge_id)
            .ok_or_else(|| ChainError::ValidationError {
                field: "challenge_id".to_string(),
                reason: "Challenge not found or expired".to_string(),
            })?;

        // Check if challenge has expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs();

        if now > challenge.expires_at {
            return Err(ChainError::ValidationError {
                field: "challenge".to_string(),
                reason: "Challenge has expired".to_string(),
            });
        }

        // Check if account matches (if specified in challenge)
        if let Some(required_account) = &challenge.account_id {
            if *required_account != account_id {
                return Err(ChainError::ValidationError {
                    field: "account_id".to_string(),
                    reason: "Account ID does not match challenge requirement".to_string(),
                });
            }
        }

        // Create challenge message to sign
        let challenge_message = self.create_challenge_message(challenge, &account_id)?;
        
        // Sign the challenge
        let challenge_hash = crate::ecc::hash::sha256(&challenge_message);
        let signature = credentials.private_key.sign(&challenge_hash)?;
        let public_key = credentials.private_key.public_key();

        Ok(LoginResponse {
            challenge_id: challenge_id.to_string(),
            account_id,
            signature: signature.to_hex(),
            public_key: public_key?.to_hex(),
            timestamp: now,
        })
    }

    /// Verify a login response and create session
    pub fn verify_and_create_session(
        &mut self,
        response: &LoginResponse,
        account: &Account,
    ) -> ChainResult<LoginSession> {
        let challenge = self.challenges.get(&response.challenge_id)
            .ok_or_else(|| ChainError::ValidationError {
                field: "challenge_id".to_string(),
                reason: "Challenge not found".to_string(),
            })?;

        // Verify account ID matches
        if response.account_id != account.id {
            return Err(ChainError::ValidationError {
                field: "account_id".to_string(),
                reason: "Account ID mismatch".to_string(),
            });
        }

        // Verify the signature
        let challenge_message = self.create_challenge_message(challenge, &response.account_id)?;
        let signature = Signature::from_hex(&response.signature)?;
        let public_key = PublicKey::from_hex(&response.public_key)?;

        if !public_key.verify_signature(&challenge_message, &signature)? {
            return Err(ChainError::ValidationError {
                field: "signature".to_string(),
                reason: "Invalid signature".to_string(),
            });
        }

        // Verify the public key is authorized for this account
        if !self.is_key_authorized(&public_key, account)? {
            return Err(ChainError::ValidationError {
                field: "authorization".to_string(),
                reason: "Public key is not authorized for this account".to_string(),
            });
        }

        // Create session
        let session = self.create_session(account.id.clone(), public_key.to_hex())?;
        
        // Remove used challenge
        self.challenges.remove(&response.challenge_id);
        
        Ok(session)
    }

    /// Create a new session
    fn create_session(&mut self, account_id: ObjectId, public_key: String) -> ChainResult<LoginSession> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs();

        let session_token = self.generate_session_token()?;
        
        let session = LoginSession {
            account_id: account_id.clone(),
            session_token: session_token.clone(),
            created_at: now,
            expires_at: now + self.session_timeout.as_secs(),
            public_key,
            metadata: HashMap::new(),
        };

        self.sessions.insert(session_token.clone(), session.clone());
        
        // Clean up expired sessions
        self.cleanup_expired_sessions();
        
        Ok(session)
    }

    /// Validate a session token
    pub fn validate_session(&self, session_token: &str) -> ChainResult<&LoginSession> {
        let session = self.sessions.get(session_token)
            .ok_or_else(|| ChainError::ValidationError {
                field: "session_token".to_string(),
                reason: "Session not found".to_string(),
            })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs();

        if now > session.expires_at {
            return Err(ChainError::ValidationError {
                field: "session".to_string(),
                reason: "Session has expired".to_string(),
            });
        }

        Ok(session)
    }

    /// Refresh a session (extend expiration)
    pub fn refresh_session(&mut self, session_token: &str) -> ChainResult<()> {
        let session = self.sessions.get_mut(session_token)
            .ok_or_else(|| ChainError::ValidationError {
                field: "session_token".to_string(),
                reason: "Session not found".to_string(),
            })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs();

        session.expires_at = now + self.session_timeout.as_secs();
        Ok(())
    }

    /// Logout (invalidate session)
    pub fn logout(&mut self, session_token: &str) -> ChainResult<()> {
        self.sessions.remove(session_token)
            .ok_or_else(|| ChainError::ValidationError {
                field: "session_token".to_string(),
                reason: "Session not found".to_string(),
            })?;
        Ok(())
    }

    /// Get session information
    pub fn get_session(&self, session_token: &str) -> Option<&LoginSession> {
        self.sessions.get(session_token)
    }

    /// List active sessions for an account
    pub fn get_account_sessions(&self, account_id: &ObjectId) -> Vec<&LoginSession> {
        self.sessions.values()
            .filter(|session| &session.account_id == account_id)
            .collect()
    }

    /// Logout all sessions for an account
    pub fn logout_account(&mut self, account_id: &ObjectId) -> usize {
        let tokens_to_remove: Vec<String> = self.sessions.iter()
            .filter(|(_, session)| &session.account_id == account_id)
            .map(|(token, _)| token.clone())
            .collect();

        let count = tokens_to_remove.len();
        for token in tokens_to_remove {
            self.sessions.remove(&token);
        }
        count
    }

    /// Check if a public key is authorized for an account
    fn is_key_authorized(&self, public_key: &PublicKey, account: &Account) -> ChainResult<bool> {
        let public_key_str = public_key.to_hex();
        
        // Check active authority
        if account.active.key_auths.contains_key(&public_key_str) {
            return Ok(true);
        }
        
        // Check owner authority
        if account.owner.key_auths.contains_key(&public_key_str) {
            return Ok(true);
        }
        
        // Check memo key
        if account.options.memo_key == public_key_str {
            return Ok(true);
        }
        
        Ok(false)
    }

    /// Create challenge message for signing
    fn create_challenge_message(&self, challenge: &LoginChallenge, account_id: &ObjectId) -> ChainResult<Vec<u8>> {
        let message = format!(
            "R-Squared Login Challenge\nChallenge ID: {}\nNonce: {}\nAccount: {}\nTimestamp: {}",
            challenge.challenge_id,
            challenge.nonce,
            account_id,
            challenge.timestamp
        );
        Ok(message.into_bytes())
    }

    /// Generate a unique challenge ID
    fn generate_challenge_id(&self) -> ChainResult<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 16] = rng.gen();
        Ok(hex::encode(random_bytes))
    }

    /// Generate a random nonce
    fn generate_nonce(&self) -> ChainResult<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        Ok(hex::encode(random_bytes))
    }

    /// Generate a session token
    fn generate_session_token(&self) -> ChainResult<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        Ok(hex::encode(random_bytes))
    }

    /// Clean up expired challenges
    fn cleanup_expired_challenges(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.challenges.retain(|_, challenge| challenge.expires_at > now);
    }

    /// Clean up expired sessions
    fn cleanup_expired_sessions(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.sessions.retain(|_, session| session.expires_at > now);
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get challenge count
    pub fn challenge_count(&self) -> usize {
        self.challenges.len()
    }

    /// Clear all sessions and challenges
    pub fn clear_all(&mut self) {
        self.sessions.clear();
        self.challenges.clear();
    }

    /// Set session metadata
    pub fn set_session_metadata(
        &mut self,
        session_token: &str,
        key: String,
        value: String,
    ) -> ChainResult<()> {
        let session = self.sessions.get_mut(session_token)
            .ok_or_else(|| ChainError::ValidationError {
                field: "session_token".to_string(),
                reason: "Session not found".to_string(),
            })?;

        session.metadata.insert(key, value);
        Ok(())
    }

    /// Get session metadata
    pub fn get_session_metadata(&self, session_token: &str, key: &str) -> Option<&String> {
        self.sessions.get(session_token)
            .and_then(|session| session.metadata.get(key))
    }
}

impl Default for AccountLogin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::PrivateKey;
    use std::collections::HashMap;

    fn create_test_account() -> Account {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        
        let mut key_auths = HashMap::new();
        key_auths.insert(public_key.to_hex(), 1);
        
        let authority = Authority {
            weight_threshold: 1,
            account_auths: HashMap::new(),
            key_auths,
            address_auths: HashMap::new(),
        };

        Account {
            id: ObjectId::new(1, 2, 1).unwrap(),
            name: "testaccount".to_string(),
            owner: authority.clone(),
            active: authority,
            options: AccountOptions {
                memo_key: public_key.to_hex(),
                voting_account: ObjectId::new(1, 2, 0).unwrap(),
                num_witness: 0,
                num_committee: 0,
                votes: vec![],
                extensions: vec![],
            },
            statistics: ObjectId::new(2, 6, 1).unwrap(),
            whitelisting_accounts: vec![],
            blacklisting_accounts: vec![],
            whitelisted_assets: vec![],
            blacklisted_assets: vec![],
            owner_special_authority: None,
            active_special_authority: None,
            top_n_control_flags: 0,
        }
    }

    #[test]
    fn test_account_login_creation() {
        let login_manager = AccountLogin::new();
        assert_eq!(login_manager.session_count(), 0);
        assert_eq!(login_manager.challenge_count(), 0);
    }

    #[test]
    fn test_credentials_from_wif() {
        let private_key = PrivateKey::generate().unwrap();
        let wif = private_key.to_wif(false);
        
        let credentials = AccountLogin::credentials_from_wif(&wif, "testaccount").unwrap();
        assert_eq!(credentials.account, "testaccount");
        assert_eq!(credentials.private_key.to_wif(false), wif);
    }

    #[test]
    fn test_create_challenge() {
        let mut login_manager = AccountLogin::new();
        let account_id = ObjectId::new(1, 2, 1).unwrap();
        
        let challenge = login_manager.create_challenge(Some(account_id)).unwrap();
        assert!(!challenge.challenge_id.is_empty());
        assert!(!challenge.nonce.is_empty());
        assert!(challenge.expires_at > challenge.timestamp);
        assert_eq!(login_manager.challenge_count(), 1);
    }

    #[test]
    fn test_respond_to_challenge() {
        let mut login_manager = AccountLogin::new();
        let account_id = ObjectId::new(1, 2, 1).unwrap();
        
        let challenge = login_manager.create_challenge(Some(account_id.clone())).unwrap();
        
        let private_key = PrivateKey::generate().unwrap();
        let credentials = LoginCredentials {
            account: "testaccount".to_string(),
            private_key,
            memo_key: None,
        };
        
        let response = login_manager.respond_to_challenge(
            &challenge.challenge_id,
            &credentials,
            account_id.clone(),
        ).unwrap();
        
        assert_eq!(response.challenge_id, challenge.challenge_id);
        assert_eq!(response.account_id, account_id);
        assert!(!response.signature.is_empty());
        assert!(!response.public_key.is_empty());
    }

    #[test]
    fn test_session_management() {
        let mut login_manager = AccountLogin::new();
        let account_id = ObjectId::new(1, 2, 1).unwrap();
        let public_key = "RSQ6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV".to_string();
        
        let session = login_manager.create_session(account_id.clone(), public_key).unwrap();
        assert_eq!(login_manager.session_count(), 1);
        
        // Validate session
        let validated = login_manager.validate_session(&session.session_token).unwrap();
        assert_eq!(validated.account_id, account_id);
        
        // Refresh session
        assert!(login_manager.refresh_session(&session.session_token).is_ok());
        
        // Logout
        assert!(login_manager.logout(&session.session_token).is_ok());
        assert_eq!(login_manager.session_count(), 0);
    }

    #[test]
    fn test_session_metadata() {
        let mut login_manager = AccountLogin::new();
        let account_id = ObjectId::new(1, 2, 1).unwrap();
        let public_key = "RSQ6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV".to_string();
        
        let session = login_manager.create_session(account_id, public_key).unwrap();
        
        // Set metadata
        login_manager.set_session_metadata(
            &session.session_token,
            "ip_address".to_string(),
            "192.168.1.1".to_string(),
        ).unwrap();
        
        // Get metadata
        let ip = login_manager.get_session_metadata(&session.session_token, "ip_address");
        assert_eq!(ip, Some(&"192.168.1.1".to_string()));
    }

    #[test]
    fn test_account_sessions() {
        let mut login_manager = AccountLogin::new();
        let account_id = ObjectId::new(1, 2, 1).unwrap();
        let public_key = "RSQ6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV".to_string();
        
        // Create multiple sessions for the same account
        login_manager.create_session(account_id.clone(), public_key.clone()).unwrap();
        login_manager.create_session(account_id.clone(), public_key).unwrap();
        
        let sessions = login_manager.get_account_sessions(&account_id);
        assert_eq!(sessions.len(), 2);
        
        // Logout all sessions for account
        let logged_out = login_manager.logout_account(&account_id);
        assert_eq!(logged_out, 2);
        assert_eq!(login_manager.session_count(), 0);
    }

    #[test]
    fn test_clear_all() {
        let mut login_manager = AccountLogin::new();
        let account_id = ObjectId::new(1, 2, 1).unwrap();
        
        // Create some sessions and challenges
        login_manager.create_challenge(Some(account_id.clone())).unwrap();
        login_manager.create_session(account_id, "test_key".to_string()).unwrap();
        
        assert!(login_manager.session_count() > 0);
        assert!(login_manager.challenge_count() > 0);
        
        login_manager.clear_all();
        
        assert_eq!(login_manager.session_count(), 0);
        assert_eq!(login_manager.challenge_count(), 0);
    }
}