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

use crate::auth::{AuthorizationError, AuthorizationEvaluator, Operation, Rule};
use crate::context::ParticipantContext;
use std::collections::HashMap;
use std::sync::RwLock;

/// A thread-safe, in-memory implementation of an authorization evaluator.
pub struct MemoryAuthorizationEvaluator {
    rules: RwLock<HashMap<String, HashMap<String, Vec<Rule>>>>,
}

impl MemoryAuthorizationEvaluator {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_rule(&self, participant_id: String, rule: Rule) {
        let mut rules = self.rules.write().unwrap();
        rules
            .entry(participant_id)
            .or_insert_with(HashMap::new)
            .entry(rule.scope.clone())
            .or_insert_with(Vec::new)
            .push(rule);
    }
}

impl AuthorizationEvaluator for MemoryAuthorizationEvaluator {
    fn evaluate(
        &self,
        participant_context: &ParticipantContext,
        operation: Operation,
    ) -> Result<bool, AuthorizationError> {
        let rules = self
            .rules
            .read()
            .map_err(|e| AuthorizationError::InternalError(format!("Failed to acquire lock: {}", e)))?;

        // Check if rules exist for this participant
        let Some(participant_rules) = rules.get(&participant_context.identifier) else {
            // No grant rules defined for this participant, not authorized
            return Ok(false);
        };
        let Some(scope_rules) = participant_rules.get(&operation.scope) else {
            // No grant rules defined for this participant and scope, not authorized
            return Ok(false);
        };

        for rule in scope_rules {
            if rule.actions.contains(&operation.action) && rule.matches_resource(&operation.resource) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
