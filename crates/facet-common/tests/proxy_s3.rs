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

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use facet_common::context::ParticipantContext;
use facet_common::jwt::{JwtVerificationError, JwtVerifier, TokenClaims};
use facet_common::proxy::s3::{
    S3Credentials, S3Proxy, StaticCredentialsResolver, StaticParticipantContextResolver, UpstreamStyle,
};
use pingora::server::Server;
use pingora::server::configuration::Opt;
use pingora_proxy::http_proxy_service;
use std::net::TcpListener;
use std::sync::Arc;
use testcontainers::core::WaitFor;
use testcontainers::{ContainerAsync, GenericImage, ImageExt, core::ContainerPort, runners::AsyncRunner};

const MINIO_ACCESS_KEY: &str = "minioadmin";
const MINIO_SECRET_KEY: &str = "minioadmin";
const TEST_BUCKET: &str = "test-bucket";
const TEST_KEY: &str = "test-file.txt";
const TEST_CONTENT: &str = "Hello from Pingora proxy test!";
const VALID_SESSION_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const INVALID_SESSION_TOKEN: &str = "invalid-token";

#[tokio::test]
async fn test_s3_proxy_with_token_validation() {
    // Start MinIO container
    let minio_container = launch_minio().await;
    let minio_port = minio_container.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    // Get an available port for the proxy
    let proxy_port = get_available_port();
    launch_s3proxy(proxy_port, minio_host.clone(), UpstreamStyle::PathStyle, None);

    setup_test_file(&minio_endpoint).await;

    // Configure SDK to use the proxy as a reverse proxy endpoint
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);

    // Test Case 1: Valid token succeeds
    let valid_config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            "",
            "",
            Some(VALID_SESSION_TOKEN.to_string()), // Valid token!
            None,
            "test",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url) // Point directly to the proxy
        .load()
        .await;

    let valid_client = Client::new(&valid_config);

    let result = valid_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(TEST_KEY)
        .send()
        .await
        .expect("Request with valid token should succeed");

    let body = result.body.collect().await.expect("Failed to read body");
    let content = String::from_utf8(body.to_vec()).expect("Invalid UTF-8");

    assert_eq!(content, TEST_CONTENT, "Content should match");

    // Test Case 2: Invalid token fails
    let invalid_config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            MINIO_ACCESS_KEY,
            MINIO_SECRET_KEY,
            Some(INVALID_SESSION_TOKEN.to_string()), // Invalid token!
            None,
            "test",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url) // Point directly to the proxy
        .load()
        .await;

    let invalid_client = Client::new(&invalid_config);

    let result = invalid_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(TEST_KEY)
        .send()
        .await;

    assert!(result.is_err(), "Request with invalid token should fail");

    // Test Case 3: Missing token fails
    let no_token_config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            MINIO_ACCESS_KEY,
            MINIO_SECRET_KEY,
            None, // No token!
            None,
            "test",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(&proxy_url) // Point directly to the proxy
        .load()
        .await;

    let no_token_client = Client::new(&no_token_config);

    let result = no_token_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(TEST_KEY)
        .send()
        .await;

    assert!(result.is_err(), "Request without token should fail");
}

/// Setup: Create the test bucket and upload the test file to MinIO
async fn setup_test_file(minio_endpoint: &String) {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(minio_endpoint)
        .load()
        .await;

    let client = Client::new(&config);

    client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("Failed to create bucket");

    client
        .put_object()
        .bucket(TEST_BUCKET)
        .key(TEST_KEY)
        .body(ByteStream::from_static(TEST_CONTENT.as_bytes()))
        .send()
        .await
        .expect("Failed to upload file");
}

/// Launches an S3 Proxy on a separate thread that validates requests against a static token.
fn launch_s3proxy(port: u16, upstream_endpoint: String, upstream_style: UpstreamStyle, proxy_domain: Option<String>) {
    std::thread::spawn(move || {
        // Create proxy with credentials for signing AND token validation
        let verifier: Arc<dyn JwtVerifier> = Arc::new(TokenMatchingJwtVerifier {
            valid_token: VALID_SESSION_TOKEN.to_string(),
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

        let proxy = S3Proxy::builder()
            .use_tls(false)
            .credential_resolver(credentials_resolver)
            .participant_context_resolver(participant_context_resolver)
            .token_verifier(verifier)
            .upstream_endpoint(upstream_endpoint)
            .upstream_style(upstream_style)
            .maybe_proxy_domain(proxy_domain)
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
}

async fn launch_minio() -> ContainerAsync<GenericImage> {
    let minio_container = GenericImage::new("minio/minio", "latest")
        .with_wait_for(WaitFor::message_on_stderr("API:"))
        .with_exposed_port(ContainerPort::Tcp(9000))
        .with_env_var("MINIO_ROOT_USER", MINIO_ACCESS_KEY)
        .with_env_var("MINIO_ROOT_PASSWORD", MINIO_SECRET_KEY)
        .with_cmd(vec!["server", "/data"])
        .start()
        .await
        .unwrap();
    minio_container
}

/// Gets an available port by binding to port 0 and retrieving the assigned port.
fn get_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port 0");
    let port = listener.local_addr().expect("Failed to get local address").port();
    drop(listener);
    port
}

/// Mock JWT verifier that validates against a specific token
struct TokenMatchingJwtVerifier {
    valid_token: String,
}

impl JwtVerifier for TokenMatchingJwtVerifier {
    fn verify_token(
        &self,
        _participant_context: &ParticipantContext,
        token: &str,
    ) -> Result<TokenClaims, JwtVerificationError> {
        if token == self.valid_token {
            Ok(TokenClaims {
                sub: "test-user".to_string(),
                iss: "test-issuer".to_string(),
                aud: "s3-proxy".to_string(),
                iat: 0,
                exp: 9999999999,
                nbf: None,
                custom: Default::default(),
            })
        } else {
            Err(JwtVerificationError::InvalidSignature)
        }
    }
}
