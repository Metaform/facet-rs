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

// Allow dead code in this module since test utilities are shared across multiple test files
// and each test binary is compiled separately
#![allow(dead_code)]

use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use facet_common::auth::MemoryAuthorizationEvaluator;
use facet_common::context::ParticipantContext;
use facet_common::jwt::{JwtVerificationError, JwtVerifier, TokenClaims};
use facet_common::proxy::s3::{S3Credentials, S3Proxy, StaticCredentialsResolver, StaticParticipantContextResolver, UpstreamStyle};
use pingora::server::configuration::Opt;
use pingora::server::Server;
use pingora_proxy::http_proxy_service;
use serde_json::Value;
use std::net::TcpListener;
use std::sync::Arc;
use testcontainers::core::WaitFor;
use testcontainers::{core::ContainerPort, runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt};

pub const MINIO_ACCESS_KEY: &str = "minioadmin";
pub const MINIO_SECRET_KEY: &str = "minioadmin";

/// Launch MinIO container for testing
pub async fn launch_minio() -> ContainerAsync<GenericImage> {
    GenericImage::new("minio/minio", "latest")
        .with_wait_for(WaitFor::message_on_stderr("API:"))
        .with_exposed_port(ContainerPort::Tcp(9000))
        .with_env_var("MINIO_ROOT_USER", MINIO_ACCESS_KEY)
        .with_env_var("MINIO_ROOT_PASSWORD", MINIO_SECRET_KEY)
        .with_cmd(vec!["server", "/data"])
        .start()
        .await
        .unwrap()
}

/// Get an available port by binding to port 0 and retrieving the assigned port
pub fn get_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port 0");
    let port = listener.local_addr().expect("Failed to get local address").port();
    drop(listener);
    port
}

/// Setup test bucket and upload initial test file
pub async fn setup_test_bucket(minio_endpoint: &str, bucket_name: &str) {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(minio_endpoint)
        .load()
        .await;

    let client = Client::new(&config);

    client
        .create_bucket()
        .bucket(bucket_name)
        .send()
        .await
        .expect("Failed to create bucket");

    // Upload a default test file
    client
        .put_object()
        .bucket(bucket_name)
        .key("test-file.txt")
        .body(ByteStream::from_static(b"test content"))
        .send()
        .await
        .expect("Failed to upload test file");
}

/// Setup test bucket and upload a specific file with content
pub async fn setup_test_bucket_with_file(
    minio_endpoint: &str,
    bucket_name: &str,
    key: &str,
    content: &[u8],
) {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(minio_endpoint)
        .load()
        .await;

    let client = Client::new(&config);

    client
        .create_bucket()
        .bucket(bucket_name)
        .send()
        .await
        .expect("Failed to create bucket");

    client
        .put_object()
        .bucket(bucket_name)
        .key(key)
        .body(ByteStream::from(content.to_vec()))
        .send()
        .await
        .expect("Failed to upload file");
}

/// Create a test S3 client configured to use the proxy
pub async fn create_test_client(proxy_url: &str, token: Option<String>) -> Client {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            "",
            "",
            token.or(Some("test-token".to_string())),
            None,
            "test",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(proxy_url)
        .load()
        .await;

    Client::new(&config)
}

/// Create a direct MinIO client (bypassing the proxy) for verification
pub async fn create_direct_minio_client(minio_endpoint: &str) -> Client {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(minio_endpoint)
        .load()
        .await;

    Client::new(&config)
}

/// Launch S3 proxy with authorization evaluator
pub fn launch_s3proxy_with_auth(
    port: u16,
    upstream_endpoint: String,
    auth_evaluator: Arc<MemoryAuthorizationEvaluator>,
    participant_id: &str,
    scope: &str,
) {
    let participant_id = participant_id.to_string();
    let scope = scope.to_string();

    std::thread::spawn(move || {
        let verifier: Arc<dyn JwtVerifier> = Arc::new(TestJwtVerifier { scope: scope.clone() });

        let credentials_resolver = Arc::new(StaticCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: MINIO_ACCESS_KEY.to_string(),
                secret_key: MINIO_SECRET_KEY.to_string(),
                region: "us-east-1".to_string(),
            },
        });

        let participant_context_resolver = Arc::new(StaticParticipantContextResolver {
            participant_context: ParticipantContext {
                identifier: participant_id,
                audience: "s3-proxy".to_string(),
            },
        });

        let proxy = S3Proxy::builder()
            .use_tls(false)
            .credential_resolver(credentials_resolver)
            .participant_context_resolver(participant_context_resolver)
            .token_verifier(verifier)
            .upstream_endpoint(upstream_endpoint)
            .upstream_style(UpstreamStyle::PathStyle)
            .maybe_proxy_domain(None)
            .auth_evaluator(auth_evaluator)
            .build();

        let mut server = Server::new(Some(Opt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None,
        }))
        .unwrap();

        server.bootstrap();

        let mut proxy_service = http_proxy_service(&server.configuration, proxy);
        proxy_service.add_tcp(&format!("0.0.0.0:{}", port));

        server.add_service(proxy_service);
        server.run_forever();
    });

    // Give the server time to start
    std::thread::sleep(std::time::Duration::from_millis(500));
}

/// Launch S3 proxy with token validation (for token-based tests)
pub fn launch_s3proxy_with_token_validation(
    port: u16,
    upstream_endpoint: String,
    upstream_style: UpstreamStyle,
    proxy_domain: Option<String>,
    valid_token: String,
    scope: String,
) {
    std::thread::spawn(move || {
        let verifier: Arc<dyn JwtVerifier> = Arc::new(TokenMatchingJwtVerifier {
            valid_token: valid_token.clone(),
            scope: scope.clone(),
        });

        let credentials_resolver = Arc::new(StaticCredentialsResolver {
            credentials: S3Credentials {
                access_key_id: MINIO_ACCESS_KEY.to_string(),
                secret_key: MINIO_SECRET_KEY.to_string(),
                region: "us-east-1".to_string(),
            },
        });

        let participant_context_resolver = Arc::new(StaticParticipantContextResolver {
            participant_context: ParticipantContext {
                identifier: "proxy".to_string(),
                audience: "s3-proxy".to_string(),
            },
        });

        let auth_evaluator = Arc::new(MemoryAuthorizationEvaluator::new());

        // Add a permissive rule for the proxy participant
        let rule = facet_common::auth::Rule::new(
            scope,
            vec!["s3:GetObject".to_string()],
            ".*".to_string(),
        )
        .expect("Failed to create authorization rule");

        auth_evaluator.add_rule("proxy".to_string(), rule);

        let proxy = S3Proxy::builder()
            .use_tls(false)
            .credential_resolver(credentials_resolver)
            .participant_context_resolver(participant_context_resolver)
            .token_verifier(verifier)
            .upstream_endpoint(upstream_endpoint)
            .upstream_style(upstream_style)
            .maybe_proxy_domain(proxy_domain)
            .auth_evaluator(auth_evaluator)
            .build();

        let mut server = Server::new(Some(Opt {
            upgrade: false,
            daemon: false,
            nocapture: false,
            test: false,
            conf: None,
        }))
        .unwrap();

        server.bootstrap();

        let mut proxy_service = http_proxy_service(&server.configuration, proxy);
        proxy_service.add_tcp(&format!("0.0.0.0:{}", port));

        server.add_service(proxy_service);
        server.run_forever();
    });

    // Give the server time to start
    std::thread::sleep(std::time::Duration::from_millis(500));
}

/// Mock JWT verifier for testing - validates against a specific scope
pub struct TestJwtVerifier {
    pub scope: String,
}

impl JwtVerifier for TestJwtVerifier {
    fn verify_token(
        &self,
        _participant_context: &ParticipantContext,
        _token: &str,
    ) -> Result<TokenClaims, JwtVerificationError> {
        let mut custom = serde_json::Map::new();
        custom.insert("scope".to_string(), Value::String(self.scope.clone()));

        Ok(TokenClaims {
            sub: "test-user".to_string(),
            iss: "test-issuer".to_string(),
            aud: "s3-proxy".to_string(),
            iat: 0,
            exp: 9999999999,
            nbf: None,
            custom,
        })
    }
}

/// Mock JWT verifier that validates against a specific token string
pub struct TokenMatchingJwtVerifier {
    pub valid_token: String,
    pub scope: String,
}

impl JwtVerifier for TokenMatchingJwtVerifier {
    fn verify_token(
        &self,
        _participant_context: &ParticipantContext,
        token: &str,
    ) -> Result<TokenClaims, JwtVerificationError> {
        let mut custom = serde_json::Map::new();
        custom.insert("scope".to_string(), Value::String(self.scope.clone()));

        if token == self.valid_token {
            Ok(TokenClaims {
                sub: "test-user".to_string(),
                iss: "test-issuer".to_string(),
                aud: "s3-proxy".to_string(),
                iat: 0,
                exp: 9999999999,
                nbf: None,
                custom,
            })
        } else {
            Err(JwtVerificationError::InvalidSignature)
        }
    }
}
