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

use crate::auth::{AuthorizationError, AuthorizationEvaluator, MemoryAuthorizationEvaluator, Operation, Rule};
use crate::context::ParticipantContext;

fn create_test_evaluator() -> MemoryAuthorizationEvaluator {
    MemoryAuthorizationEvaluator::new()
}

fn setup_rules(evaluator: &MemoryAuthorizationEvaluator, participant_id: &str, rules: Vec<Rule>) {
    for rule in rules {
        evaluator.add_rule(participant_id.to_string(), rule);
    }
}

#[test]
fn test_evaluate_authorized_exact_match() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "read".to_string(),
            resource: "resource1".to_string(),
        },
    );

    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_evaluate_no_rules_for_participant() {
    let evaluator = create_test_evaluator();

    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "unknown_participant".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "read".to_string(),
            resource: "resource1".to_string(),
        },
    );

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_evaluate_no_rules_for_scope() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "scope1".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "scope2".to_string(),
            action: "read".to_string(),
            resource: "resource1".to_string(),
        },
    );

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_evaluate_action_not_authorized() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "write".to_string(),
            resource: "resource1".to_string(),
        },
    );

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_evaluate_resource_not_matching() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "read".to_string(),
            resource: "resource2".to_string(),
        },
    );

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_evaluate_regex_pattern_matching() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^/api/users/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    // Should match the pattern
    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "read".to_string(),
            resource: "/api/users/123".to_string(),
        },
    );
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Should not match the pattern
    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "read".to_string(),
            resource: "/api/posts/123".to_string(),
        },
    );
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_evaluate_multiple_actions_in_rule() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string(), "write".to_string(), "delete".to_string()],
            "^resource1$".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    // All three actions should be authorized
    for action in &["read", "write", "delete"] {
        let result = evaluator.evaluate(
            &ParticipantContext {
                identifier: "participant1".to_string(),
                audience: "test_audience".to_string(),
            },
            Operation {
                scope: "test_scope".to_string(),
                action: action.to_string(),
                resource: "resource1".to_string(),
            },
        );
        assert!(result.is_ok());
        assert!(result.unwrap(), "Action {} should be authorized", action);
    }
}

#[test]
fn test_evaluate_multiple_rules() {
    let evaluator = create_test_evaluator();
    let rules = vec![
        Rule::new(
            "test_scope".to_string(),
            vec!["read".to_string()],
            "^/api/users/.*".to_string(),
        )
        .unwrap(),
        Rule::new(
            "test_scope".to_string(),
            vec!["write".to_string()],
            "^/api/posts/.*".to_string(),
        )
        .unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    // First rule should match
    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "read".to_string(),
            resource: "/api/users/456".to_string(),
        },
    );
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Second rule should match
    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "write".to_string(),
            resource: "/api/posts/789".to_string(),
        },
    );
    assert!(result.is_ok());
    assert!(result.unwrap());

    // No rule should match (wrong action for resource)
    let result = evaluator.evaluate(
        &ParticipantContext {
            identifier: "participant1".to_string(),
            audience: "test_audience".to_string(),
        },
        Operation {
            scope: "test_scope".to_string(),
            action: "write".to_string(),
            resource: "/api/users/456".to_string(),
        },
    );
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_rule_invalid_regex() {
    let result = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "[invalid(".to_string(),
    );

    assert!(result.is_err());
    match result {
        Err(AuthorizationError::InvalidRegex(_)) => {}
        _ => panic!("Expected InvalidRegex error"),
    }
}

#[test]
fn test_rule_matches_resource() {
    let rule = Rule::new(
        "test_scope".to_string(),
        vec!["read".to_string()],
        "^/api/.*".to_string(),
    )
    .unwrap();

    assert!(rule.matches_resource("/api/users"));
    assert!(rule.matches_resource("/api/posts/123"));
    assert!(!rule.matches_resource("/v2/api/users"));
    assert!(!rule.matches_resource("api/users"));
}
