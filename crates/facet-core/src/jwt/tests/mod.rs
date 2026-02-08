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

use crate::context::ParticipantContext;
use crate::jwt::jwtutils::{
    generate_ed25519_keypair_der, generate_ed25519_keypair_pem, generate_rsa_keypair_pem,
    SigningKeyRecord, VaultSigningKeyResolver,
};
use crate::jwt::{JwtGenerator, JwtVerificationError, JwtVerifier, TokenClaims};
use crate::jwt::{KeyFormat, LocalJwtGenerator, LocalJwtVerifier, SigningAlgorithm};
use crate::test_fixtures::{StaticSigningKeyResolver, StaticVerificationKeyResolver};
use crate::vault::{MemoryVaultClient, VaultClient};
use chrono::Utc;
use rstest::rstest;
use std::sync::Arc;

/// Helper function to create a JWT generator for testing
fn create_test_generator(
    private_key: Vec<u8>,
    iss: &str,
    kid: &str,
    key_format: KeyFormat,
    signing_algorithm: SigningAlgorithm,
) -> LocalJwtGenerator {
    let signing_resolver = Arc::new(
        StaticSigningKeyResolver::builder()
            .key(private_key)
            .iss(iss)
            .kid(kid)
            .key_format(key_format)
            .build(),
    );

    LocalJwtGenerator::builder()
        .signing_key_resolver(signing_resolver)
        .signing_algorithm(signing_algorithm)
        .build()
}

/// Helper function to create a JWT verifier for testing
fn create_test_verifier(
    public_key: Vec<u8>,
    key_format: KeyFormat,
    signing_algorithm: SigningAlgorithm,
) -> LocalJwtVerifier {
    let verification_resolver = Arc::new(
        StaticVerificationKeyResolver::builder()
            .key(public_key)
            .key_format(key_format)
            .build(),
    );

    LocalJwtVerifier::builder()
        .verification_key_resolver(verification_resolver)
        .signing_algorithm(signing_algorithm)
        .build()
}

/// Helper function to create a JWT verifier with leeway for testing
fn create_test_verifier_with_leeway(
    public_key: Vec<u8>,
    key_format: KeyFormat,
    signing_algorithm: SigningAlgorithm,
    leeway_seconds: u64,
) -> LocalJwtVerifier {
    let verification_resolver = Arc::new(
        StaticVerificationKeyResolver::builder()
            .key(public_key)
            .key_format(key_format)
            .build(),
    );

    LocalJwtVerifier::builder()
        .verification_key_resolver(verification_resolver)
        .signing_algorithm(signing_algorithm)
        .leeway_seconds(leeway_seconds)
        .build()
}

#[rstest]
#[case(KeyFormat::PEM)]
#[case(KeyFormat::DER)]
#[tokio::test]
async fn test_token_generation_validation(#[case] key_format: KeyFormat) {
    let keypair = match key_format {
        KeyFormat::PEM => generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair"),
        KeyFormat::DER => generate_ed25519_keypair_der().expect("Failed to generate DER keypair"),
    };

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        key_format.clone(),
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience1")
        .exp(now + 10000)
        .custom({
            let mut custom = serde_json::Map::new();
            custom.insert(
                "access_token".to_string(),
                serde_json::Value::String("token-value".to_string()),
            );
            custom
        })
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant1")
        .audience("audience1")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, key_format, SigningAlgorithm::EdDSA);

    let verified_claims = verifier
        .verify_token(pc, token.as_str())
        .expect("Token verification should succeed");

    assert_eq!(verified_claims.sub, "user-id-123");
    assert_eq!(verified_claims.iss, "user-id-123");
    assert_eq!(verified_claims.exp, now + 10000);
    assert_eq!(
        verified_claims.custom.get("access_token").unwrap(),
        &serde_json::Value::String("token-value".to_string())
    );
}

#[tokio::test]
async fn test_expired_token_validation_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now - 10000) // Expired 10,000 seconds ago
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    let result = verifier.verify_token(pc, token.as_str());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenExpired));
}

#[tokio::test]
async fn test_leeway_allows_recently_expired_token_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "issuer-leeway",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-789")
        .aud("audience1")
        .exp(now - 20) // Expired 20 seconds ago
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant1")
        .audience("audience1")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verifier with 30-second leeway should accept token expired 20 seconds ago
    let verifier = create_test_verifier_with_leeway(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA, 30);

    let verified_claims = verifier
        .verify_token(pc, token.as_str())
        .expect("Token should be valid with leeway");

    assert_eq!(verified_claims.sub, "user-id-789");
    assert_eq!(verified_claims.iss, "issuer-leeway");
}

#[tokio::test]
async fn test_leeway_rejects_token_expired_beyond_leeway_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-999")
        .iss("issuer-expired")
        .aud("audience-123")
        .exp(now - 100) // Expired 100 seconds ago
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verifier with 30-second leeway should reject token expired 100 seconds ago
    let verifier = create_test_verifier_with_leeway(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA, 30);

    let result = verifier.verify_token(pc, token.as_str());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenExpired));
}

#[tokio::test]
async fn test_invalid_signature_pem_eddsa() {
    let keypair1 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 1");
    let keypair2 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 2");

    let generator = create_test_generator(
        keypair1.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now + 10000)
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    // Try to verify with a different public key
    let verifier = create_test_verifier(keypair2.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    let result = verifier.verify_token(pc, token.as_str());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidSignature));
}

#[tokio::test]
async fn test_malformed_token_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    let pc = &ParticipantContext::builder()
        .id("participant1")
        .audience("audience1")
        .build();

    // Empty token string
    let result = verifier.verify_token(pc, "");
    assert!(result.is_err(), "Empty token should fail validation");
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidFormat));

    // Token with only one dot (missing signature part)
    let result = verifier.verify_token(pc, "header.payload");
    assert!(result.is_err(), "Token missing signature should fail validation");
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidFormat));

    // Token with invalid base64 in parts
    let result = verifier.verify_token(pc, "not.a.token");
    assert!(result.is_err(), "Token with invalid base64 should fail validation");
    match result.unwrap_err() {
        JwtVerificationError::InvalidFormat | JwtVerificationError::VerificationFailed(_) => {}
        other => panic!("Expected InvalidFormat or VerificationFailed, got {:?}", other),
    }

    // Token with no dots at all
    let result = verifier.verify_token(pc, "invalid-token");
    assert!(result.is_err(), "Token with no dots should fail validation");
    assert!(matches!(result.unwrap_err(), JwtVerificationError::InvalidFormat));
}

#[tokio::test]
async fn test_mismatched_key_format_pem_eddsa() {
    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let keypair_pem = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair_pem.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now + 10000)
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    let keypair_der = generate_ed25519_keypair_der().expect("Failed to generate DER keypair");

    let verifier = create_test_verifier(keypair_der.public_key, KeyFormat::DER, SigningAlgorithm::EdDSA);

    let result = verifier.verify_token(pc, token.as_str());

    // This should fail because we're using a different keypair
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rsa_token_generation_validation_pem() {
    let keypair = generate_rsa_keypair_pem().expect("Failed to generate RSA PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "issuer-rsa",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::RS256,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-456")
        .aud("audience1")
        .exp(now + 10000)
        .custom({
            let mut custom = serde_json::Map::new();
            custom.insert("scope".to_string(), serde_json::Value::String("read:data".to_string()));
            custom
        })
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant1")
        .audience("audience1")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::RS256);

    let verified_claims = verifier
        .verify_token(pc, token.as_str())
        .expect("Token verification should succeed");

    assert_eq!(verified_claims.sub, "user-id-456");
    assert_eq!(verified_claims.iss, "issuer-rsa");
    assert_eq!(verified_claims.exp, now + 10000);
    assert_eq!(
        verified_claims.custom.get("scope").unwrap(),
        &serde_json::Value::String("read:data".to_string())
    );
}

#[tokio::test]
async fn test_audience_mismatch_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now + 10000)
        .build();

    let pc_generate = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc_generate, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    // Try to verify with a different audience
    let pc_verify = &ParticipantContext::builder()
        .id("participant-1")
        .audience("different-audience")
        .build();

    let result = verifier.verify_token(pc_verify, token.as_str());

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        JwtVerificationError::VerificationFailed(_)
    ));
}

#[tokio::test]
async fn test_algorithm_mismatch_pem() {
    let keypair_eddsa = generate_ed25519_keypair_pem().expect("Failed to generate EdDSA keypair");
    let keypair_rsa = generate_rsa_keypair_pem().expect("Failed to generate RSA keypair");

    // Generate token with EdDSA
    let generator = create_test_generator(
        keypair_eddsa.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .exp(now + 10000)
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    // Try to verify EdDSA token with RS256 verifier
    let verifier = create_test_verifier(keypair_rsa.public_key, KeyFormat::PEM, SigningAlgorithm::RS256);

    let result = verifier.verify_token(pc, token.as_str());

    // Should fail due to algorithm mismatch
    assert!(result.is_err());
}

#[tokio::test]
async fn test_not_before_validation_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .nbf(now + 10000) // Not valid for another 10,000 seconds
        .exp(now + 20000)
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    let result = verifier.verify_token(pc, token.as_str());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenNotYetValid));
}

#[tokio::test]
async fn test_not_before_with_leeway_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-456")
        .iss("user-id-123")
        .aud("audience-123")
        .nbf(now + 20) // Not valid for another 20 seconds
        .exp(now + 10000)
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verifier with 30-second leeway should accept token with nbf 20 seconds in the future
    let verifier = create_test_verifier_with_leeway(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA, 30);

    let verified_claims = verifier
        .verify_token(pc, token.as_str())
        .expect("Token should be valid with leeway");

    assert_eq!(verified_claims.sub, "user-id-456");
    assert_eq!(verified_claims.nbf, Some(now + 20));
}

#[tokio::test]
async fn test_not_before_beyond_leeway_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-789")
        .iss("user-id-123")
        .aud("audience-123")
        .nbf(now + 100) // Not valid for another 100 seconds
        .exp(now + 10000)
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verifier with 30-second leeway should reject token with nbf 100 seconds in the future
    let verifier = create_test_verifier_with_leeway(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA, 30);

    let result = verifier.verify_token(pc, token.as_str());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtVerificationError::TokenNotYetValid));
}

#[tokio::test]
async fn test_generator_sets_iat_automatically_pem_eddsa() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let generator = create_test_generator(
        keypair.private_key,
        "user-id-123",
        "did:web:example.com#key-1",
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let before_generation = Utc::now().timestamp();

    // Set iat to a specific old value that should be ignored
    let old_iat = 1609459200; // 2021-01-01 00:00:00 UTC
    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123")
        .aud("audience-123")
        .iat(old_iat) // This should be ignored by the generator
        .exp(now + 10000)
        .build();

    let pc = &ParticipantContext::builder()
        .id("participant-1")
        .audience("audience-123")
        .build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    let after_generation = Utc::now().timestamp();

    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    let verified_claims = verifier
        .verify_token(pc, token.as_str())
        .expect("Token verification should succeed");

    // Verify that the iat claim was set to current time, NOT the old value we passed in
    assert_ne!(
        verified_claims.iat, old_iat,
        "Generator should ignore the iat value passed in TokenClaims"
    );
    assert!(
        verified_claims.iat >= before_generation && verified_claims.iat <= after_generation,
        "Generator should set iat to current timestamp. Expected between {} and {}, got {}",
        before_generation,
        after_generation,
        verified_claims.iat
    );
}

#[tokio::test]
async fn test_kid_and_iss_are_set_correctly_in_generated_token() {
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate PEM keypair");

    let expected_iss = "did:web:example.com";
    let expected_kid = "did:web:example.com#key-1";

    let generator = create_test_generator(
        keypair.private_key,
        expected_iss,
        expected_kid,
        KeyFormat::PEM,
        SigningAlgorithm::EdDSA,
    );

    let now = Utc::now().timestamp();

    let claims = TokenClaims::builder()
        .sub("user-id-123")
        .iss("user-id-123") // This will be overwritten by the generator
        .aud("audience1")
        .exp(now + 10000)
        .build();

    let pc = &ParticipantContext::builder().id("participant1").build();

    let token = generator
        .generate_token(pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verify kid in header
    let header = jsonwebtoken::decode_header(token.as_str()).expect("Should be able to decode header");
    assert_eq!(header.kid, Some(expected_kid.to_string()), "kid header should match");

    // Verify iss in claims
    let unverified_claims = jsonwebtoken::dangerous::insecure_decode::<TokenClaims>(token.as_str())
        .expect("Should be able to decode claims")
        .claims;
    assert_eq!(unverified_claims.iss, expected_iss, "iss claim should match");
}

#[tokio::test]
async fn test_vault_signing_key_resolver_successful_resolution() {
    // Setup vault client with a stored key
    let keypair = generate_ed25519_keypair_pem().expect("Failed to generate keypair");
    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc = ParticipantContext::builder()
        .id("test-participant")
        .identifier("did:web:example.com")
        .audience("test-audience")
        .build();

    // Create and store a SigningKeyRecord as JSON in the vault
    let key_record = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair.private_key).unwrap())
        .kid("did:web:example.com#key-1")
        .key_format(KeyFormat::PEM)
        .build();

    let key_record_json = serde_json::to_string(&key_record).expect("Failed to serialize SigningKeyRecord");

    vault_client
        .store_secret(&pc, "signing-key", &key_record_json)
        .await
        .expect("Failed to store secret");

    // Create the vault signing key resolver
    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("signing-key")
            .build(),
    );

    // Create generator with vault resolver
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 10000)
        .build();

    // Generate token
    let token = generator
        .generate_token(&pc, claims)
        .await
        .expect("Token generation should succeed");

    // Verify the token with the public key
    let verifier = create_test_verifier(keypair.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);

    let verified_claims = verifier
        .verify_token(&pc, token.as_str())
        .expect("Token verification should succeed");

    assert_eq!(verified_claims.sub, "user-123");
    assert_eq!(verified_claims.iss, "did:web:example.com");
}

#[tokio::test]
async fn test_vault_signing_key_resolver_missing_key() {
    // Setup vault client without storing a key
    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc = ParticipantContext::builder()
        .id("test-participant")
        .identifier("did:web:example.com")
        .audience("test-audience")
        .build();

    // Create the vault signing key resolver
    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("missing-key")
            .build(),
    );

    // Create generator with vault resolver
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();
    let claims = TokenClaims::builder()
        .sub("user-123")
        .aud("test-audience")
        .exp(now + 10000)
        .build();

    // Attempt to generate token should fail
    let result = generator.generate_token(&pc, claims).await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Failed to resolve signing key from vault"),
        "Error message should mention vault resolution failure"
    );
}

#[tokio::test]
async fn test_vault_signing_key_resolver_different_participants() {
    // Setup vault client with keys for different participants
    let keypair1 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 1");
    let keypair2 = generate_ed25519_keypair_pem().expect("Failed to generate keypair 2");

    let vault_client = Arc::new(MemoryVaultClient::new());

    let pc1 = ParticipantContext::builder()
        .id("participant-1")
        .identifier("did:web:example.com")
        .audience("audience-1")
        .build();

    let pc2 = ParticipantContext::builder()
        .id("participant-2")
        .identifier("did:web:example.com")
        .audience("audience-2")
        .build();

    // Create and store SigningKeyRecords as JSON for each participant
    let key_record1 = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair1.private_key).unwrap())
        .kid("did:web:example.com#key-1")
        .key_format(KeyFormat::PEM)
        .build();

    let key_record1_json = serde_json::to_string(&key_record1).expect("Failed to serialize SigningKeyRecord");

    vault_client
        .store_secret(&pc1, "signing-key", &key_record1_json)
        .await
        .expect("Failed to store secret for participant 1");

    let key_record2 = SigningKeyRecord::builder()
        .private_key(std::str::from_utf8(&keypair2.private_key).unwrap())
        .kid("did:web:example.com#key-2")
        .key_format(KeyFormat::PEM)
        .build();

    let key_record2_json = serde_json::to_string(&key_record2).expect("Failed to serialize SigningKeyRecord");

    vault_client
        .store_secret(&pc2, "signing-key", &key_record2_json)
        .await
        .expect("Failed to store secret for participant 2");

    // Create the vault signing key resolver
    let vault_resolver = Arc::new(
        VaultSigningKeyResolver::builder()
            .vault_client(vault_client)
            .base_path("signing-key")
            .build(),
    );

    // Create generator
    let generator = LocalJwtGenerator::builder()
        .signing_key_resolver(vault_resolver)
        .signing_algorithm(SigningAlgorithm::EdDSA)
        .build();

    let now = Utc::now().timestamp();

    // Generate token for participant 1
    let claims1 = TokenClaims::builder()
        .sub("user-123")
        .aud("audience-1")
        .exp(now + 10000)
        .build();

    let token1 = generator
        .generate_token(&pc1, claims1)
        .await
        .expect("Token generation for participant 1 should succeed");

    // Generate token for participant 2
    let claims2 = TokenClaims::builder()
        .sub("user-456")
        .aud("audience-2")
        .exp(now + 10000)
        .build();

    let token2 = generator
        .generate_token(&pc2, claims2)
        .await
        .expect("Token generation for participant 2 should succeed");

    // Verify token 1 with keypair 1
    let verifier1 = create_test_verifier(keypair1.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let verified_claims1 = verifier1
        .verify_token(&pc1, token1.as_str())
        .expect("Token 1 verification should succeed");
    assert_eq!(verified_claims1.sub, "user-123");

    // Verify token 2 with keypair 2
    let verifier2 = create_test_verifier(keypair2.public_key, KeyFormat::PEM, SigningAlgorithm::EdDSA);
    let verified_claims2 = verifier2
        .verify_token(&pc2, token2.as_str())
        .expect("Token 2 verification should succeed");
    assert_eq!(verified_claims2.sub, "user-456");

    // Verify token 1 with keypair 2 should fail
    let result = verifier2.verify_token(&pc1, token1.as_str());
    assert!(result.is_err());
}

#[test]
fn test_signing_key_record_serialization() {
    // Create a SigningKeyRecord
    let record = SigningKeyRecord::builder()
        .private_key("test-private-key-content")
        .kid("did:web:example.com#key-123")
        .key_format(KeyFormat::PEM)
        .build();

    // Serialize to JSON
    let json = serde_json::to_string(&record).expect("Failed to serialize");

    // Verify JSON contains expected fields
    assert!(json.contains("private_key"));
    assert!(json.contains("test-private-key-content"));
    assert!(json.contains("kid"));
    assert!(json.contains("did:web:example.com#key-123"));
    assert!(json.contains("key_format"));
    assert!(json.contains("PEM"));

    // Deserialize back
    let deserialized: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");

    // Verify fields match
    assert_eq!(deserialized.private_key, "test-private-key-content");
    assert_eq!(deserialized.kid, "did:web:example.com#key-123");
    assert_eq!(deserialized.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_round_trip() {
    // Test with a real-looking PEM key
    let pem_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAbcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP\n-----END PRIVATE KEY-----";

    let original = SigningKeyRecord::builder()
        .private_key(pem_key)
        .kid("did:web:example.org#signing-key-1")
        .key_format(KeyFormat::DER)
        .build();

    // Serialize and deserialize
    let json = serde_json::to_string(&original).expect("Failed to serialize");
    let roundtrip: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");

    // Verify exact match
    assert_eq!(original.private_key, roundtrip.private_key);
    assert_eq!(original.kid, roundtrip.kid);
    assert_eq!(original.key_format, roundtrip.key_format);
}

#[test]
fn test_signing_key_record_pretty_json() {
    let record = SigningKeyRecord::builder()
        .private_key("my-private-key")
        .kid("my-kid")
        .key_format(KeyFormat::PEM)
        .build();

    // Test pretty JSON formatting
    let pretty_json = serde_json::to_string_pretty(&record).expect("Failed to serialize");

    // Should be multi-line
    assert!(pretty_json.contains('\n'));

    // Should deserialize correctly
    let deserialized: SigningKeyRecord = serde_json::from_str(&pretty_json).expect("Failed to deserialize");
    assert_eq!(deserialized.private_key, "my-private-key");
    assert_eq!(deserialized.kid, "my-kid");
    assert_eq!(deserialized.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_default_key_format() {
    // Test that key_format defaults to PEM when not specified
    let record = SigningKeyRecord::builder()
        .private_key("test-key")
        .kid("test-kid")
        .build();

    assert_eq!(record.key_format, KeyFormat::PEM);
}

#[test]
fn test_signing_key_record_with_der_format() {
    // Test with DER format
    let record = SigningKeyRecord::builder()
        .private_key("der-key-content")
        .kid("did:web:test.com#key-der")
        .key_format(KeyFormat::DER)
        .build();

    let json = serde_json::to_string(&record).expect("Failed to serialize");
    assert!(json.contains("DER"));

    let deserialized: SigningKeyRecord = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(deserialized.key_format, KeyFormat::DER);
    assert_eq!(deserialized.private_key, "der-key-content");
}
