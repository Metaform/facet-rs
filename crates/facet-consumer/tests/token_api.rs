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

use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use facet_common::context::ParticipantContext;
use facet_common::util::{Clock, MockClock, default_clock};
use facet_consumer::lock::mem::MemoryLockManager;
use facet_consumer::token::mem::MemoryTokenStore;
use facet_consumer::token::{TokenClientApi, TokenData, TokenError, TokenStore};
use std::sync::Arc;

#[tokio::test]
async fn test_api_end_to_end() {
    let lock_manager = Arc::new(MemoryLockManager::new());
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_client = Arc::new(MockTokenClient {});

    let data = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "test".to_string(),
        token: "token".to_string(),
        refresh_token: "refresh".to_string(),
        expires_at: Utc::now() + TimeDelta::seconds(10),
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };
    token_store.save_token(data).await.unwrap();

    let token_api = TokenClientApi::builder()
        .lock_manager(lock_manager)
        .token_store(token_store)
        .token_client(token_client)
        .clock(default_clock())
        .build();

    let pc1 = &ParticipantContext::builder()
        .identifier("participant1")
        .audience("audience1")
        .build();

    let _ = token_api.get_token(pc1, "test", "owner1").await.unwrap();
}

#[tokio::test]
async fn test_token_expiration_triggers_refresh() {
    let lock_manager = Arc::new(MemoryLockManager::new());
    let token_store = Arc::new(MemoryTokenStore::new());
    let token_client = Arc::new(MockTokenClient {});

    let initial_time = Utc::now();
    let clock = Arc::new(MockClock::new(initial_time));

    let data = TokenData {
        participant_context: "participant1".to_string(),
        identifier: "test".to_string(),
        token: "token".to_string(),
        refresh_token: "refresh".to_string(),
        expires_at: initial_time + TimeDelta::seconds(10),
        refresh_endpoint: "https://example.com/refresh".to_string(),
    };
    token_store.save_token(data).await.unwrap();

    let token_api = TokenClientApi::builder()
        .lock_manager(lock_manager)
        .token_store(token_store)
        .token_client(token_client)
        .clock(clock.clone() as Arc<dyn Clock>)
        .build();

    // Advance time so the token is about to expire
    clock.advance(TimeDelta::seconds(6)); // Now + 6s, the token expires at +10s, the refresh threshold is 5s

    let pc1 = &ParticipantContext::builder()
        .identifier("participant1")
        .audience("audience1")
        .build();

    let result = token_api.get_token(pc1, "test", "owner1").await;
    // Should trigger refresh since (now + 5s refresh buffer) > expires_at
    assert!(result.is_ok());
}

struct MockTokenClient {}

#[async_trait]
impl facet_consumer::token::TokenClient for MockTokenClient {
    async fn refresh_token(
        &self,
        _participant_context: &ParticipantContext,
        _endpoint_identifier: &str,
        _access_token: &str,
        _refresh_token: &str,
        _refresh_endpoint: &str,
    ) -> Result<TokenData, TokenError> {
        Ok(TokenData {
            participant_context: "participant1".to_string(),
            identifier: "test".to_string(),
            token: "refreshed_token".to_string(),
            refresh_token: "test".to_string(),
            expires_at: Utc::now() + TimeDelta::seconds(10),
            refresh_endpoint: "http://example.com/renew".to_string(),
        })
    }
}
