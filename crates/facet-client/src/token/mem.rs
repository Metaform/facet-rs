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

use crate::token::{TokenData, TokenError, TokenStore};
use crate::util::{default_clock, Clock};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory token store for testing and development.
///
/// Maintains tokens in a thread-safe hashmap. Not suitable for production use.
pub struct MemoryTokenStore {
    tokens: RwLock<HashMap<String, TokenRecord>>,
    clock: Arc<dyn Clock>,
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            clock: default_clock(),
        }
    }

    #[cfg(test)]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            clock,
        }
    }

    /// Remove all tokens that were last accessed before the specified time
    pub async fn remove_tokens_accessed_before(&self, cutoff: DateTime<Utc>) -> Result<usize, TokenError> {
        let mut tokens = self.tokens.write().await;
        let initial_count = tokens.len();
        tokens.retain(|_, record| record.last_accessed > cutoff);
        let removed_count = initial_count - tokens.len();
        Ok(removed_count)
    }
}

impl Default for MemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

struct TokenRecord {
    #[allow(dead_code)]
    identifier: String,
    token: String,
    refresh_token: String,
    refresh_endpoint: String,
    expires_at: DateTime<Utc>,
    last_accessed: DateTime<Utc>,
}

#[async_trait]
impl TokenStore for MemoryTokenStore {
    async fn get_token(&self, identifier: &str) -> Result<TokenData, TokenError> {
        let tokens = self.tokens.read().await;
        tokens
            .get(identifier)
            .map(|record| TokenData {
                identifier: identifier.to_string(),
                token: record.token.clone(),
                refresh_token: record.refresh_token.clone(),
                expires_at: record.expires_at,
                refresh_endpoint: record.refresh_endpoint.clone(),
            })
            .ok_or_else(|| TokenError::token_not_found(identifier))
    }

    async fn save_token(&self, data: TokenData) -> Result<(), TokenError> {
        let record = TokenRecord {
            identifier: data.identifier.clone(),
            token: data.token,
            expires_at: data.expires_at,
            refresh_token: data.refresh_token,
            refresh_endpoint: data.refresh_endpoint,
            last_accessed: self.clock.now(),
        };

        self.tokens.write().await.insert(data.identifier, record);
        Ok(())
    }

    async fn update_token(&self, data: TokenData) -> Result<(), TokenError> {
        let mut tokens = self.tokens.write().await;

        if !tokens.contains_key(&data.identifier) {
            return Err(TokenError::cannot_update_non_existent(&data.identifier));
        }

        let now = self.clock.now();
        tokens.entry(data.identifier).and_modify(|record| {
            record.token = data.token.clone();
            record.refresh_token = data.refresh_token.clone();
            record.expires_at = data.expires_at;
            record.refresh_endpoint = data.refresh_endpoint;
            record.last_accessed = now;
        });

        Ok(())
    }

    async fn remove_token(&self, identifier: &str) -> Result<(), TokenError> {
        self.tokens.write().await.remove(identifier);
        Ok(())
    }

    async fn close(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::MockClock;
    use chrono::Duration as ChronoDuration;

    async fn create_store_with_tokens() -> MemoryTokenStore {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now() + ChronoDuration::seconds(10);

        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save token");

        store
            .save_token(TokenData {
                identifier: "user2".to_string(),
                token: "token2".to_string(),
                refresh_token: "refresh2".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save token");

        store
            .save_token(TokenData {
                identifier: "user3".to_string(),
                token: "token3".to_string(),
                refresh_token: "refresh3".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save token");

        store
    }

    #[tokio::test]
    async fn test_new_store_is_empty() {
        let store = MemoryTokenStore::new();
        let data = store.get_token("nonexistent").await;
        assert!(data.is_err());
    }

    #[tokio::test]
    async fn test_save_token_success() {
        let store = MemoryTokenStore::new();
        let expiration = Utc::now() + ChronoDuration::seconds(10);
        let test_data = TokenData {
            identifier: "user1".to_string(),
            token: "token123".to_string(),
            refresh_token: "refresh123".to_string(),
            expires_at: expiration,
            refresh_endpoint: "https://example.com/refresh".to_string(),
        };

        let result = store.save_token(test_data.clone()).await;
        assert!(result.is_ok(), "save_token should return Ok");

        let retrieved = store.get_token("user1").await.expect("Failed to retrieve saved token");
        assert_eq!(retrieved.identifier, "user1", "Identifier should match");
        assert_eq!(retrieved.token, "token123", "Token should match");
        assert_eq!(retrieved.refresh_token, "refresh123", "Refresh token should match");
        assert_eq!(retrieved.expires_at, expiration, "Expiration should match");
        assert_eq!(
            retrieved.refresh_endpoint, "https://example.com/refresh",
            "Refresh endpoint should match"
        );
    }

    #[tokio::test]
    async fn test_save_multiple_tokens() {
        let store = create_store_with_tokens().await;

        assert_eq!(store.get_token("user1").await.unwrap().token, "token1");
        assert_eq!(store.get_token("user2").await.unwrap().token, "token2");
        assert_eq!(store.get_token("user3").await.unwrap().token, "token3");
    }

    #[tokio::test]
    async fn test_remove_tokens_used_before_success() {
        let initial = Utc::now();
        let clock = Arc::new(MockClock::new(initial));
        let store = MemoryTokenStore::with_clock(clock.clone());
        let expiration = initial + ChronoDuration::seconds(10);

        store
            .save_token(TokenData {
                identifier: "user1".to_string(),
                token: "token1".to_string(),
                refresh_token: "refresh1".to_string(),
                expires_at: expiration,
                refresh_endpoint: "https://example.com/refresh".to_string(),
            })
            .await
            .expect("Failed to save");

        let cutoff = clock.now() + ChronoDuration::seconds(1);

        let removed = store
            .remove_tokens_accessed_before(cutoff)
            .await
            .expect("Failed to remove tokens");

        assert_eq!(removed, 1);
        assert!(store.get_token("user1").await.is_err());
    }
}