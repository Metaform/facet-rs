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

use crate::auth::{AuthorizationError, AuthorizationEvaluator, MemoryAuthorizationEvaluator, Operation, Rule, RuleStore};
use crate::context::ParticipantContext;

fn create_test_evaluator() -> MemoryAuthorizationEvaluator {
    MemoryAuthorizationEvaluator::new()
}

fn setup_rules(evaluator: &MemoryAuthorizationEvaluator, participant_id: &str, rules: Vec<Rule>) {
    let ctx = &ParticipantContext {
        identifier: participant_id.to_string(),
        audience: "test-audience".to_string(),
    };

    for rule in rules {
        evaluator.save_rule(ctx, rule).unwrap();
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

#[test]
fn test_get_rules_no_rules() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };

    let result = evaluator.get_rules(&ctx);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_get_rules_single_rule() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule.clone()).unwrap();

    let result = evaluator.get_rules(&ctx);
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].scope, "scope1");
    assert_eq!(rules[0].actions, vec!["read"]);
}

#[test]
fn test_get_rules_multiple_scopes() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };

    let rules = vec![
        Rule::new("scope1".to_string(), vec!["read".to_string()], "^resource1$".to_string()).unwrap(),
        Rule::new("scope2".to_string(), vec!["write".to_string()], "^resource2$".to_string()).unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    let result = evaluator.get_rules(&ctx);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[test]
fn test_get_rules_same_scope() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };

    let rules = vec![
        Rule::new("scope1".to_string(), vec!["read".to_string()], "^resource1$".to_string()).unwrap(),
        Rule::new("scope1".to_string(), vec!["write".to_string()], "^resource2$".to_string()).unwrap(),
    ];
    setup_rules(&evaluator, "participant1", rules);

    let result = evaluator.get_rules(&ctx);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[test]
fn test_save_rule() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let result = evaluator.save_rule(&ctx, rule);
    assert!(result.is_ok());

    let rules = evaluator.get_rules(&ctx).unwrap();
    assert_eq!(rules.len(), 1);
}

#[test]
fn test_save_multiple_rules_same_participant() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };

    let rule1 = Rule::new("scope1".to_string(), vec!["read".to_string()], "^resource1$".to_string()).unwrap();
    let rule2 = Rule::new("scope2".to_string(), vec!["write".to_string()], "^resource2$".to_string()).unwrap();

    evaluator.save_rule(&ctx, rule1).unwrap();
    evaluator.save_rule(&ctx, rule2).unwrap();

    let rules = evaluator.get_rules(&ctx).unwrap();
    assert_eq!(rules.len(), 2);
}

#[test]
fn test_save_rules_different_participants() {
    let evaluator = create_test_evaluator();
    let ctx1 = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };
    let ctx2 = ParticipantContext {
        identifier: "participant2".to_string(),
        audience: "test-audience".to_string(),
    };

    let rule = Rule::new("scope1".to_string(), vec!["read".to_string()], "^resource1$".to_string()).unwrap();

    evaluator.save_rule(&ctx1, rule.clone()).unwrap();
    evaluator.save_rule(&ctx2, rule).unwrap();

    assert_eq!(evaluator.get_rules(&ctx1).unwrap().len(), 1);
    assert_eq!(evaluator.get_rules(&ctx2).unwrap().len(), 1);
}

#[test]
fn test_remove_rule_exists() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule.clone()).unwrap();
    assert_eq!(evaluator.get_rules(&ctx).unwrap().len(), 1);

    let result = evaluator.remove_rule(&ctx, rule);
    assert!(result.is_ok());
    assert_eq!(evaluator.get_rules(&ctx).unwrap().len(), 0);
}

#[test]
fn test_remove_rule_not_exists() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let result = evaluator.remove_rule(&ctx, rule);
    assert!(result.is_ok());
}

#[test]
fn test_remove_rule_participant_not_exists() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "unknown".to_string(),
        audience: "test-audience".to_string(),
    };
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    let result = evaluator.remove_rule(&ctx, rule);
    assert!(result.is_ok());
}

#[test]
fn test_remove_rule_multiple_in_scope() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };

    let rule1 = Rule::new("scope1".to_string(), vec!["read".to_string()], "^resource1$".to_string()).unwrap();
    let rule2 = Rule::new("scope1".to_string(), vec!["write".to_string()], "^resource2$".to_string()).unwrap();

    evaluator.save_rule(&ctx, rule1.clone()).unwrap();
    evaluator.save_rule(&ctx, rule2).unwrap();
    assert_eq!(evaluator.get_rules(&ctx).unwrap().len(), 2);

    evaluator.remove_rule(&ctx, rule1).unwrap();
    assert_eq!(evaluator.get_rules(&ctx).unwrap().len(), 1);
}

#[test]
fn test_remove_last_rule_cleans_scope() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };

    let rule1 = Rule::new("scope1".to_string(), vec!["read".to_string()], "^resource1$".to_string()).unwrap();
    let rule2 = Rule::new("scope2".to_string(), vec!["write".to_string()], "^resource2$".to_string()).unwrap();

    evaluator.save_rule(&ctx, rule1.clone()).unwrap();
    evaluator.save_rule(&ctx, rule2).unwrap();

    evaluator.remove_rule(&ctx, rule1).unwrap();

    let rules = evaluator.get_rules(&ctx).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].scope, "scope2");
}

#[test]
fn test_remove_last_rule_cleans_participant() {
    let evaluator = create_test_evaluator();
    let ctx = ParticipantContext {
        identifier: "participant1".to_string(),
        audience: "test-audience".to_string(),
    };
    let rule = Rule::new(
        "scope1".to_string(),
        vec!["read".to_string()],
        "^resource1$".to_string(),
    )
    .unwrap();

    evaluator.save_rule(&ctx, rule.clone()).unwrap();
    evaluator.remove_rule(&ctx, rule).unwrap();

    assert_eq!(evaluator.get_rules(&ctx).unwrap().len(), 0);
}
