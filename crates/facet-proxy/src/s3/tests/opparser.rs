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

use crate::s3::S3OperationParser;
use crate::s3::opparser::DefaultS3OperationParser;
use pingora_http::RequestHeader;

// ==================== Object GET Operations ====================

#[test]
fn test_get_object() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.scope, "test-scope");
    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_get_object_nested_key() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/path/to/object.txt");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/path/to/object.txt");
}

#[test]
fn test_get_object_acl() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?acl");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObjectAcl");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_get_object_tagging() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?tagging");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObjectTagging");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_get_object_torrent() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?torrent");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObjectTorrent");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_get_object_legal_hold() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?legal-hold");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObjectLegalHold");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_get_object_retention() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?retention");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObjectRetention");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_get_object_version() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?versionId=abc123");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObjectVersion");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_head_object() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("HEAD", "/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/key");
}

// ==================== Object PUT Operations ====================

#[test]
fn test_put_object() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:PutObject");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_put_object_nested_key() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/documents/report.pdf");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:PutObject");
    assert_eq!(op.resource, "/bucket/documents/report.pdf");
}

#[test]
fn test_put_object_acl() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/key?acl");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:PutObjectAcl");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_put_object_tagging() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/key?tagging");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:PutObjectTagging");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_put_object_legal_hold() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/key?legal-hold");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:PutObjectLegalHold");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_put_object_retention() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/key?retention");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:PutObjectRetention");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_restore_object() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/key?restore");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:RestoreObject");
    assert_eq!(op.resource, "/bucket/key");
}

// ==================== Object DELETE Operations ====================

#[test]
fn test_delete_object() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("DELETE", "/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:DeleteObject");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_delete_object_nested_key() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("DELETE", "/bucket/folder/subfolder/file.txt");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:DeleteObject");
    assert_eq!(op.resource, "/bucket/folder/subfolder/file.txt");
}

// ==================== Object POST Operations ====================

#[test]
fn test_post_object() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("POST", "/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:PutObject");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_post_delete_batch() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("POST", "/bucket?delete");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:DeleteObject");
    assert_eq!(op.resource, "/bucket");
}

// ==================== Bucket-level GET Operations ====================

#[test]
fn test_list_bucket_v2() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket?list-type=2");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:ListBucket");
    assert_eq!(op.resource, "/bucket");
}

#[test]
fn test_list_bucket_v2_with_prefix() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket?list-type=2&prefix=folder/");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:ListBucket");
    assert_eq!(op.resource, "/bucket");
}

#[test]
fn test_list_bucket_v2_with_delimiter() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket?list-type=2&delimiter=/");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:ListBucket");
    assert_eq!(op.resource, "/bucket");
}

#[test]
fn test_list_bucket_versions() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket?versions");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:ListBucketVersions");
    assert_eq!(op.resource, "/bucket");
}

#[test]
fn test_list_bucket_multipart_uploads() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket?uploads");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:ListBucketMultipartUploads");
    assert_eq!(op.resource, "/bucket");
}

#[test]
fn test_get_bucket_location() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket?location");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetBucketLocation");
    assert_eq!(op.resource, "/bucket");
}

// ==================== Edge Cases and Complex Scenarios ====================

#[test]
fn test_uri_with_http_scheme() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "http://s3.amazonaws.com/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_uri_with_https_scheme() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "https://s3.amazonaws.com/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_multiple_query_parameters() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?versionId=abc123&response-content-type=text/plain");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObjectVersion");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_acl_with_version_id() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?acl&versionId=abc123");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    // The parser checks for 'acl' first, so it should return GetObjectAcl
    assert_eq!(op.action, "s3:GetObjectAcl");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_bucket_only_path() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    // Without list-type or other bucket-level query params, this is still GetObject
    // (could be a bucket-level operation, but the parser treats it as object)
    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket");
}

#[test]
fn test_bucket_with_trailing_slash() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/");
}

#[test]
fn test_key_with_special_characters() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/path%20with%20spaces/file.txt");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/path%20with%20spaces/file.txt");
}

#[test]
fn test_key_with_plus_sign() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/file+name.txt");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/file+name.txt");
}

#[test]
fn test_empty_query_value() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?acl=");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:GetObjectAcl");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_unknown_query_parameter() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key?custom-param=value");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    // Unknown query parameter should default to GetObject
    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_multipart_upload_related() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/key?uploadId=xyz&partNumber=1");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    // Without explicit handling, this defaults to PutObject
    assert_eq!(op.action, "s3:PutObject");
    assert_eq!(op.resource, "/bucket/key");
}

// ==================== Scope Verification ====================

#[test]
fn test_custom_scope() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key");
    let op = parser.parse_operation("custom-scope:read", &req).unwrap();

    assert_eq!(op.scope, "custom-scope:read");
    assert_eq!(op.action, "s3:GetObject");
}

#[test]
fn test_empty_scope() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/bucket/key");
    let op = parser.parse_operation("", &req).unwrap();

    assert_eq!(op.scope, "");
    assert_eq!(op.action, "s3:GetObject");
}

// ==================== Method-based Fallback Tests ====================

#[test]
fn test_options_method_fallback() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("OPTIONS", "/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    // OPTIONS should use the fallback pattern
    assert_eq!(op.action, "s3:optionsObject");
    assert_eq!(op.resource, "/bucket/key");
}

#[test]
fn test_patch_method_fallback() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PATCH", "/bucket/key");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    // PATCH should use the fallback pattern
    assert_eq!(op.action, "s3:patchObject");
    assert_eq!(op.resource, "/bucket/key");
}

// ==================== Real-world Scenarios ====================

#[test]
fn test_s3_console_list_operation() {
    let parser = DefaultS3OperationParser::new();
    // AWS S3 Console uses list-type=2 for listing
    let req = create_request(
        "GET",
        "/my-bucket?list-type=2&delimiter=/&encoding-type=url&max-keys=300&prefix=",
    );
    let op = parser.parse_operation("console", &req).unwrap();

    assert_eq!(op.action, "s3:ListBucket");
    assert_eq!(op.resource, "/my-bucket");
}

#[test]
fn test_s3_cli_get_with_range() {
    let parser = DefaultS3OperationParser::new();
    // AWS CLI might add range parameters
    let req = create_request("GET", "/bucket/large-file.dat?part-number=1");
    let op = parser.parse_operation("cli", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/large-file.dat");
}

#[test]
fn test_cloudfront_signed_url() {
    let parser = DefaultS3OperationParser::new();
    // CloudFront signed URLs have many query parameters
    let req = create_request(
        "GET",
        "/bucket/protected/video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE",
    );
    let op = parser.parse_operation("cdn", &req).unwrap();

    assert_eq!(op.action, "s3:GetObject");
    assert_eq!(op.resource, "/bucket/protected/video.mp4");
}

#[test]
fn test_versioned_bucket_list() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("GET", "/versioned-bucket?versions&max-keys=1000");
    let op = parser.parse_operation("backup", &req).unwrap();

    assert_eq!(op.action, "s3:ListBucketVersions");
    assert_eq!(op.resource, "/versioned-bucket");
}

#[test]
fn test_tagging_operation_with_value() {
    let parser = DefaultS3OperationParser::new();
    let req = create_request("PUT", "/bucket/key?tagging=");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    assert_eq!(op.action, "s3:PutObjectTagging");
    assert_eq!(op.resource, "/bucket/key");
}

// ==================== Priority Testing (which query param takes precedence) ====================

#[test]
fn test_query_param_priority_acl_before_tagging() {
    let parser = DefaultS3OperationParser::new();
    // When both acl and tagging are present, acl should be checked first
    let req = create_request("GET", "/bucket/key?acl&tagging");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    // Based on the implementation, acl comes before tagging in the match
    assert_eq!(op.action, "s3:GetObjectAcl");
}

#[test]
fn test_bucket_operation_detection_with_object_query() {
    let parser = DefaultS3OperationParser::new();
    // Query parameters are processed in iteration order
    // list-type appears first, so it takes precedence
    let req = create_request("GET", "/bucket/key?list-type=2&acl");
    let op = parser.parse_operation("test-scope", &req).unwrap();

    // list-type is encountered first during iteration, so ListBucket is returned
    assert_eq!(op.action, "s3:ListBucket");
}

/// Helper function to create a RequestHeader for testing
fn create_request(method: &str, uri: &str) -> RequestHeader {
    let mut req = RequestHeader::build(method, uri.as_bytes(), None).unwrap();
    req.insert_header("Host", "test-bucket.s3.amazonaws.com").unwrap();
    req
}
