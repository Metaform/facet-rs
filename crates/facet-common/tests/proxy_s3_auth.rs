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

mod common;

use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use facet_common::auth::{MemoryAuthorizationEvaluator, Rule};
use std::sync::Arc;
use crate::common::{
    create_direct_minio_client, create_test_client, get_available_port, launch_minio,
    launch_s3proxy_with_auth, setup_test_bucket, MINIO_ACCESS_KEY, MINIO_SECRET_KEY,
};

const TEST_BUCKET: &str = "test-bucket";

// ==================== Object GET Operations - Allow ====================

#[tokio::test]
async fn test_e2e_allow_get_object() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:GetObject".to_string()],
        format!("^/{}/test-file.txt$", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: GET through proxy should succeed
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_ok(), "Should allow GetObject with correct permissions");

    // Verify: Check content matches what's in MinIO
    let body = result.unwrap().body.collect().await.unwrap();
    let content = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(content, "test content", "Content should match MinIO data");

    // Verify: Direct MinIO client can also read the same file
    let direct_client = create_direct_minio_client(&minio_endpoint).await;
    let direct_result = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(direct_result.is_ok(), "File should exist in MinIO");
}

#[tokio::test]
async fn test_e2e_allow_get_object_with_wildcard() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:GetObject".to_string()],
        format!("^/{}/.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: GET through proxy should succeed
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_ok(), "Should allow GetObject with wildcard pattern");

    // Verify: File content matches MinIO
    let body = result.unwrap().body.collect().await.unwrap();
    let content = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(content, "test content");
}

#[tokio::test]
async fn test_e2e_allow_head_object() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:GetObject".to_string()],
        format!("^/{}/.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: HEAD through proxy should succeed
    let result = client
        .head_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_ok(), "HEAD should use same permission as GET");

    // Verify: Object exists in MinIO and has correct metadata
    let direct_client = create_direct_minio_client(&minio_endpoint).await;
    let direct_head = direct_client
        .head_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(direct_head.is_ok(), "Object should exist in MinIO");
}

// ==================== Object PUT Operations - Allow ====================

#[tokio::test]
async fn test_e2e_allow_put_object() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:PutObject".to_string()],
        format!("^/{}/.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: PUT through proxy should succeed
    let result = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("new-file.txt")
        .body(ByteStream::from_static(b"new content"))
        .send()
        .await;

    assert!(result.is_ok(), "Should allow PutObject with correct permissions");

    // Verify: Object was created in MinIO with correct content
    let direct_client = create_direct_minio_client(&minio_endpoint).await;
    let verify = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("new-file.txt")
        .send()
        .await;
    assert!(verify.is_ok(), "Object should exist in MinIO");
    let body = verify.unwrap().body.collect().await.unwrap();
    assert_eq!(body.into_bytes().as_ref(), b"new content", "Content should match");
}

// ==================== Object DELETE Operations - Allow ====================

#[tokio::test]
async fn test_e2e_allow_delete_object() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:DeleteObject".to_string()],
        format!("^/{}/.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: DELETE through proxy should succeed
    let result = client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_ok(), "Should allow DeleteObject with correct permissions");

    // Verify: Object was deleted from MinIO
    let direct_client = create_direct_minio_client(&minio_endpoint).await;
    let verify = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(verify.is_err(), "Object should not exist in MinIO after deletion");
}

// ==================== Bucket Operations - Allow ====================

#[tokio::test]
async fn test_e2e_allow_list_bucket() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:ListBucket".to_string()],
        format!("^/{}/?$", TEST_BUCKET), // Allow optional trailing slash
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test: LIST through proxy should succeed
    let result = client.list_objects_v2().bucket(TEST_BUCKET).send().await;

    assert!(result.is_ok(), "Should allow ListBucket with correct permissions");

    // Verify: Direct MinIO list shows the same object count
    let proxy_count = result.unwrap().contents().len();
    let direct_client = create_direct_minio_client(&minio_endpoint).await;
    let direct_result = direct_client
        .list_objects_v2()
        .bucket(TEST_BUCKET)
        .send()
        .await;
    assert!(direct_result.is_ok());
    assert_eq!(direct_result.unwrap().contents().len(), proxy_count, "List counts should match");
}

// ==================== Deny Scenarios ====================

#[tokio::test]
async fn test_e2e_deny_wrong_action() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    // Only allow GetObject
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:GetObject".to_string()],
        format!("^/{}/.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Try to PUT (not allowed)
    let result = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("unauthorized.txt")
        .body(ByteStream::from_static(b"content"))
        .send()
        .await;

    assert!(result.is_err(), "Should deny PutObject without permission");

    // Verify: Object was NOT created in MinIO
    let direct_client = create_direct_minio_client(&minio_endpoint).await;
    let verify = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("unauthorized.txt")
        .send()
        .await;
    assert!(verify.is_err(), "Unauthorized object should not exist in MinIO");
}

#[tokio::test]
async fn test_e2e_deny_wrong_resource_pattern() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    // Only allow access to /public/* path
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:GetObject".to_string()],
        format!("^/{}/public/.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Try to access file not in /public/
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_err(), "Should deny access to files outside allowed pattern");

    // Verify: Original file still exists in MinIO (access was denied, not deleted)
    let direct_client = create_direct_minio_client(&minio_endpoint).await;
    let verify = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(verify.is_ok(), "Original file should still exist in MinIO");
}

#[tokio::test]
async fn test_e2e_deny_read_only_user_trying_to_write() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    // Read-only permissions
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:GetObject".to_string(), "s3:ListBucket".to_string()],
        format!("^/{}.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("readonly_user".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "readonly_user", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Try to delete (not allowed)
    let result = client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;

    assert!(result.is_err(), "Read-only user should not be able to delete");

    // Verify: File still exists in MinIO
    let direct_client = create_direct_minio_client(&minio_endpoint).await;
    let verify = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(verify.is_ok(), "File should still exist after failed delete");
}

// ==================== Multiple Actions ====================

#[tokio::test]
async fn test_e2e_multiple_actions_in_single_rule() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec![
            "s3:GetObject".to_string(),
            "s3:PutObject".to_string(),
            "s3:DeleteObject".to_string(),
        ],
        format!("^/{}/.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user1".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user1", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Test GET
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(result.is_ok(), "Should allow GET");

    // Test PUT
    let result = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("new-file.txt")
        .body(ByteStream::from_static(b"content"))
        .send()
        .await;
    assert!(result.is_ok(), "Should allow PUT");

    // Test DELETE
    let result = client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(result.is_ok(), "Should allow DELETE");

    // Verify: All operations succeeded in MinIO
    let direct_client = create_direct_minio_client(&minio_endpoint).await;

    // new-file.txt should exist
    let verify_put = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("new-file.txt")
        .send()
        .await;
    assert!(verify_put.is_ok(), "PUT file should exist");

    // test-file.txt should be deleted
    let verify_delete = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(verify_delete.is_err(), "Deleted file should not exist");
}

// ==================== General Scenarios ====================

#[tokio::test]
async fn test_e2e_readonly_access_to_entire_bucket() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());

    let rule1 = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:GetObject".to_string()],
        format!("^/{}/.*", TEST_BUCKET),
    )
    .unwrap();

    let rule2 = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:ListBucket".to_string()],
        format!("^/{}/?$", TEST_BUCKET), // Allow optional trailing slash
    )
    .unwrap();

    evaluator.add_rule("analyst".to_string(), rule1);
    evaluator.add_rule("analyst".to_string(), rule2);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "analyst", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Can list bucket
    let result = client.list_objects_v2().bucket(TEST_BUCKET).send().await;
    assert!(result.is_ok(), "Should allow list");

    // Can read objects
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(result.is_ok(), "Should allow read");

    // Cannot write
    let result = client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("new.txt")
        .body(ByteStream::from_static(b"data"))
        .send()
        .await;
    assert!(result.is_err(), "Should deny write");

    // Cannot delete
    let result = client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key("test-file.txt")
        .send()
        .await;
    assert!(result.is_err(), "Should deny delete");
}

#[tokio::test]
async fn test_e2e_folder_specific_access() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    // Upload files to different folders
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&minio_endpoint)
        .load()
        .await;
    let setup_client = Client::new(&config);

    setup_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("users/user123/file.txt")
        .body(ByteStream::from_static(b"user123 data"))
        .send()
        .await
        .unwrap();

    setup_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("users/user456/file.txt")
        .body(ByteStream::from_static(b"user456 data"))
        .send()
        .await
        .unwrap();

    // User can only access their own folder
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec![
            "s3:GetObject".to_string(),
            "s3:PutObject".to_string(),
            "s3:DeleteObject".to_string(),
        ],
        format!("^/{}/users/user123/.*", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("user123".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "user123", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Can access own folder
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("users/user123/file.txt")
        .send()
        .await;
    assert!(result.is_ok(), "Should access own folder");

    // Cannot access another user's folder
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("users/user456/file.txt")
        .send()
        .await;
    assert!(result.is_err(), "Should not access other user's folder");
}

#[tokio::test]
async fn test_e2e_regex_pattern_with_file_extension() {
    let minio = launch_minio().await;
    let minio_port = minio.get_host_port_ipv4(9000).await.unwrap();
    let minio_host = format!("127.0.0.1:{}", minio_port);
    let minio_endpoint = format!("http://{}", minio_host);

    setup_test_bucket(&minio_endpoint, TEST_BUCKET).await;

    // Upload files with different extensions
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(&minio_endpoint)
        .load()
        .await;
    let setup_client = Client::new(&config);

    setup_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("image.jpg")
        .body(ByteStream::from_static(b"image data"))
        .send()
        .await
        .unwrap();

    setup_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("document.pdf")
        .body(ByteStream::from_static(b"pdf data"))
        .send()
        .await
        .unwrap();

    // Only allow access to image files
    let evaluator = Arc::new(MemoryAuthorizationEvaluator::new());
    let rule = Rule::new(
        TEST_BUCKET.to_string(),
        vec!["s3:GetObject".to_string()],
        format!(r"^/{}/.*\.(jpg|jpeg|png|gif)$", TEST_BUCKET),
    )
    .unwrap();
    evaluator.add_rule("image-processor".to_string(), rule);

    let proxy_port = get_available_port();
    launch_s3proxy_with_auth(proxy_port, minio_host, evaluator, "image-processor", TEST_BUCKET);

    let client = create_test_client(&format!("http://127.0.0.1:{}", proxy_port), None).await;

    // Can access image files
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("image.jpg")
        .send()
        .await;
    assert!(result.is_ok(), "Should allow access to image files");

    // Cannot access non-image files
    let result = client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("document.pdf")
        .send()
        .await;
    assert!(result.is_err(), "Should deny access to non-image files");
}
