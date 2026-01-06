//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

pub mod mem;
pub mod postgres;

pub use mem::MemoryTokenStore;
pub use postgres::PostgresTokenStore;

const FIVE_SECONDS_MILLIS: i64 = 5_000;

use crate::lock::{LockGuard, LockManager};
use crate::util::{Clock, default_clock};
use async_trait::async_trait;
use bon::Builder;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token not found for identifier: {identifier}")]
    TokenNotFound { identifier: String },

    #[error("Cannot update non-existent token '{identifier}'")]
    CannotUpdateNonExistent { identifier: String },

    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl TokenError {
    pub fn token_not_found(identifier: impl Into<String>) -> Self {
        TokenError::TokenNotFound {
            identifier: identifier.into(),
        }
    }

    pub fn cannot_update_non_existent(identifier: impl Into<String>) -> Self {
        TokenError::CannotUpdateNonExistent {
            identifier: identifier.into(),
        }
    }

    pub fn database_error(message: impl Into<String>) -> Self {
        TokenError::DatabaseError(message.into())
    }
}

/// Manages token lifecycle with automatic refresh and distributed coordination.
///
/// Coordinates retrieval and refresh of tokens from a remote authorization server,
/// using a lock manager to prevent concurrent refresh attempts. Automatically refreshes
/// expiring tokens before returning them.
#[derive(Clone, Builder)]
pub struct TokenClientApi {
    lock_manager: Arc<dyn LockManager>,
    token_store: Arc<dyn TokenStore>,
    token_client: Arc<dyn TokenClient>,
    #[builder(default = FIVE_SECONDS_MILLIS)]
    refresh_before_expiry_ms: i64,
    #[builder(default = default_clock())]
    clock: Arc<dyn Clock>,
}

impl TokenClientApi {
    pub async fn get_token(&self, identifier: &str, owner: &str) -> Result<String, TokenError> {
        let data = self.token_store.get_token(identifier).await?;

        let token =
            if self.clock.now() >= (data.expires_at - ChronoDuration::milliseconds(self.refresh_before_expiry_ms)) {
                // Token is expiring, refresh it
                self.lock_manager
                    .lock(identifier, owner)
                    .await
                    .map_err(|e| TokenError::database_error(format!("Failed to acquire lock: {}", e)))?;

                let guard = LockGuard {
                    lock_manager: self.lock_manager.clone(),
                    identifier: identifier.to_string(),
                    owner: owner.to_string(),
                };

                let refreshed_data = self
                    .token_client
                    .refresh_token(&data.refresh_token, &data.refresh_endpoint)
                    .await?;
                self.token_store.update_token(refreshed_data.clone()).await?;
                drop(guard);
                refreshed_data.token
            } else {
                data.token
            };

        Ok(token)
    }
}

/// Refreshes expired tokens with a remote authorization server.
///
/// Implementations handle the details of communicating with a token endpoint to obtain fresh tokens using a refresh
/// token.
#[async_trait]
pub trait TokenClient: Send + Sync {
    async fn refresh_token(&self, refresh_token: &str, refresh_endpoint: &str) -> Result<TokenData, TokenError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenData {
    pub identifier: String,
    pub token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_endpoint: String,
}

/// Persists and retrieves tokens with optional expiration tracking.
///
/// Implementations provide storage and retrieval of token data, typically including access tokens, refresh tokens, and
/// expiration times. The storage backend (in-memory, database, etc.) is implementation-dependent.
#[async_trait]
pub trait TokenStore: Send + Sync {
    async fn get_token(&self, identifier: &str) -> Result<TokenData, TokenError>;
    async fn save_token(&self, data: TokenData) -> Result<(), TokenError>;
    async fn update_token(&self, data: TokenData) -> Result<(), TokenError>;
    async fn remove_token(&self, identifier: &str) -> Result<(), TokenError>;
    async fn close(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::lock::MemoryLockManager;
    use crate::util::MockClock;
    use chrono::{Duration, Utc};
    use mockall::mock;
    use mockall::predicate::*;
    use std::sync::Arc;

    mock! {
        TokenClient {}

        #[async_trait::async_trait]
        impl TokenClient for TokenClient {
            async fn refresh_token(&self, refresh_token: &str, refresh_endpoint: &str) -> Result<TokenData, TokenError>;
        }
    }

    #[tokio::test]
    async fn test_get_token_not_expiring_does_not_refresh() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client.expect_refresh_token().never();

        let data = TokenData {
            identifier: "test".to_string(),
            token: "active_token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: initial_time + Duration::seconds(60),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };
        token_store.save_token(data).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager)
            .token_store(token_store)
            .token_client(Arc::new(token_client))
            .clock(clock)
            .refresh_before_expiry_ms(5_000)
            .build();

        let result = token_api.get_token("test", "owner1").await.unwrap();
        assert_eq!(result, "active_token");
    }

    #[tokio::test]
    async fn test_get_token_expiring_soon_triggers_refresh() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client
            .expect_refresh_token()
            .once()
            .with(eq("old_refresh"), eq("https://example.com/refresh"))
            .returning(|_, _| {
                Ok(TokenData {
                    identifier: "test".to_string(),
                    token: "new_token".to_string(),
                    refresh_token: "new_refresh".to_string(),
                    expires_at: Utc::now() + Duration::seconds(3600),
                    refresh_endpoint: "https://example.com/refresh".to_string(),
                })
            });

        let data = TokenData {
            identifier: "test".to_string(),
            token: "old_token".to_string(),
            refresh_token: "old_refresh".to_string(),
            expires_at: initial_time + Duration::seconds(10),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };
        token_store.save_token(data).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager)
            .token_store(token_store)
            .token_client(Arc::new(token_client))
            .clock(clock.clone())
            .refresh_before_expiry_ms(5_000)
            .build();

        // Advance time so the token is within the 5s refresh threshold
        clock.advance(Duration::seconds(6));

        let result = token_api.get_token("test", "owner1").await.unwrap();
        assert_eq!(result, "new_token");
    }

    #[tokio::test]
    async fn test_get_token_expired_triggers_refresh() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client.expect_refresh_token().once().returning(|_, _| {
            Ok(TokenData {
                identifier: "test".to_string(),
                token: "refreshed_token".to_string(),
                refresh_token: "new_refresh".to_string(),
                expires_at: Utc::now() + Duration::seconds(3600),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

        let data = TokenData {
            identifier: "test".to_string(),
            token: "expired_token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: initial_time - Duration::seconds(10),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };
        token_store.save_token(data).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager)
            .token_store(token_store)
            .token_client(Arc::new(token_client))
            .clock(clock)
            .build();

        let result = token_api.get_token("test", "owner1").await.unwrap();
        assert_eq!(result, "refreshed_token");
    }

    #[tokio::test]
    async fn test_refresh_updates_stored_token() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client.expect_refresh_token().once().returning(|_, _| {
            Ok(TokenData {
                identifier: "test".to_string(),
                token: "refreshed_token".to_string(),
                refresh_token: "new_refresh_token".to_string(),
                expires_at: Utc::now() + Duration::seconds(3600),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

        let data = TokenData {
            identifier: "test".to_string(),
            token: "old_token".to_string(),
            refresh_token: "old_refresh".to_string(),
            expires_at: initial_time + Duration::seconds(3),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };
        token_store.save_token(data).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager)
            .token_store(token_store.clone())
            .token_client(Arc::new(token_client))
            .clock(clock.clone())
            .refresh_before_expiry_ms(5_000)
            .build();

        clock.advance(Duration::seconds(4));
        let _ = token_api.get_token("test", "owner1").await.unwrap();

        // Verify the stored token was updated
        let updated = token_store.get_token("test").await.unwrap();
        assert_eq!(updated.token, "refreshed_token");
        assert_eq!(updated.refresh_token, "new_refresh_token");
    }

    #[tokio::test]
    async fn test_refresh_failure_returns_error() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client
            .expect_refresh_token()
            .once()
            .returning(|_, _| Err(TokenError::database_error("Refresh endpoint unavailable")));

        let data = TokenData {
            identifier: "test".to_string(),
            token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: initial_time + Duration::seconds(3),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };
        token_store.save_token(data).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager)
            .token_store(token_store)
            .token_client(Arc::new(token_client))
            .clock(clock.clone())
            .refresh_before_expiry_ms(5_000)
            .build();

        clock.advance(Duration::seconds(4));
        let result = token_api.get_token("test", "owner1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_lock_acquired_during_refresh() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client.expect_refresh_token().once().returning(|_, _| {
            Ok(TokenData {
                identifier: "test".to_string(),
                token: "refreshed".to_string(),
                refresh_token: "new_refresh".to_string(),
                expires_at: Utc::now() + Duration::seconds(3600),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

        let data = TokenData {
            identifier: "test".to_string(),
            token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: initial_time + Duration::seconds(3),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };
        token_store.save_token(data).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager.clone())
            .token_store(token_store)
            .token_client(Arc::new(token_client))
            .clock(clock.clone())
            .refresh_before_expiry_ms(5_000)
            .build();

        clock.advance(Duration::seconds(4));

        // Trigger refresh which should acquire the lock
        let _ = token_api.get_token("test", "owner1").await.unwrap();

        // Verify that the lock was eventually released (allow brief time for async drop)
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // If lock is released, another owner should be able to acquire it
        let lock_result = lock_manager.lock("test", "owner2").await;
        assert!(lock_result.is_ok(), "Lock should be released after refresh");
    }

    #[tokio::test]
    async fn test_lock_prevents_concurrent_refresh() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client.expect_refresh_token().never(); // Refresh should NOT happen since lock cannot be acquired

        let data = TokenData {
            identifier: "test".to_string(),
            token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: initial_time + Duration::seconds(3),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };
        token_store.save_token(data).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager.clone())
            .token_store(token_store.clone())
            .token_client(Arc::new(token_client))
            .clock(clock.clone())
            .refresh_before_expiry_ms(5_000)
            .build();

        clock.advance(Duration::seconds(4));

        // Manually acquire lock to simulate another process
        lock_manager.lock("test", "other_owner").await.unwrap();

        // Attempt to get token should fail (cannot acquire lock)
        let result = token_api.get_token("test", "owner1").await;
        assert!(result.is_err(), "Should fail when lock is held by another owner");
    }

    #[tokio::test]
    async fn test_token_not_found_error() {
        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client.expect_refresh_token().never();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager)
            .token_store(token_store)
            .token_client(Arc::new(token_client))
            .build();

        let result = token_api.get_token("nonexistent", "owner1").await;
        assert!(result.is_err());

        match result.unwrap_err() {
            TokenError::TokenNotFound { identifier } => {
                assert_eq!(identifier, "nonexistent");
            }
            _ => panic!("Expected TokenNotFound error"),
        }
    }

    #[tokio::test]
    async fn test_refresh_with_custom_refresh_threshold() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client.expect_refresh_token().once().returning(|_, _| {
            Ok(TokenData {
                identifier: "test".to_string(),
                token: "refreshed".to_string(),
                refresh_token: "new_refresh".to_string(),
                expires_at: Utc::now() + Duration::seconds(3600),
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
        });

        let data = TokenData {
            identifier: "test".to_string(),
            token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: initial_time + Duration::seconds(20),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };
        token_store.save_token(data).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager)
            .token_store(token_store)
            .token_client(Arc::new(token_client))
            .clock(clock.clone())
            .refresh_before_expiry_ms(10_000) // Refresh 10 seconds before expiry
            .build();

        clock.advance(Duration::seconds(11));

        let result = token_api.get_token("test", "owner1").await.unwrap();
        assert_eq!(result, "refreshed");
    }

    #[tokio::test]
    async fn test_multiple_tokens_independent_refresh() {
        let initial_time = Utc::now();
        let clock = Arc::new(MockClock::new(initial_time));

        let lock_manager = Arc::new(MemoryLockManager::new());
        let token_store = Arc::new(MemoryTokenStore::new());

        let mut token_client = MockTokenClient::new();
        token_client
            .expect_refresh_token()
            .once()
            .with(eq("refresh1"), eq("https://example.com/refresh"))
            .returning(|_, _| {
                Ok(TokenData {
                    identifier: "token1".to_string(),
                    token: "refreshed1".to_string(),
                    refresh_token: "new_refresh1".to_string(),
                    expires_at: Utc::now() + Duration::seconds(3600),
                    refresh_endpoint: "https://example.com/refresh".to_string(),
                })
            });

        let data1 = TokenData {
            identifier: "token1".to_string(),
            token: "token1".to_string(),
            refresh_token: "refresh1".to_string(),
            expires_at: initial_time + Duration::seconds(3),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };

        let data2 = TokenData {
            identifier: "token2".to_string(),
            token: "token2".to_string(),
            refresh_token: "refresh2".to_string(),
            expires_at: initial_time + Duration::seconds(100),
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };

        token_store.save_token(data1).await.unwrap();
        token_store.save_token(data2).await.unwrap();

        let token_api = TokenClientApi::builder()
            .lock_manager(lock_manager)
            .token_store(token_store)
            .token_client(Arc::new(token_client))
            .clock(clock.clone())
            .refresh_before_expiry_ms(5_000)
            .build();

        clock.advance(Duration::seconds(4));

        // token1 should trigger refresh
        let result1 = token_api.get_token("token1", "owner1").await.unwrap();
        assert_eq!(result1, "refreshed1");

        // token2 should not refresh
        let result2 = token_api.get_token("token2", "owner1").await.unwrap();
        assert_eq!(result2, "token2");
    }
}
