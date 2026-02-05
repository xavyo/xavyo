//! Performance benchmarks for policy evaluation.
//!
//! These benchmarks verify the <10ms performance target for single policy evaluation.
//! Three complexity levels are tested:
//! - Simple: 1-3 rules (single permission check)
//! - Medium: 4-9 rules (role-based access with conditions)
//! - Complex: 10+ rules (multi-factor authorization)

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;
use uuid::Uuid;
use xavyo_authorization::types::{AuthorizationRequest, ConditionData, PolicyWithConditions};
use xavyo_authorization::PolicyEvaluator;

/// Create a test authorization request.
fn create_request() -> AuthorizationRequest {
    AuthorizationRequest {
        subject_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        action: "read".to_string(),
        resource_type: "document".to_string(),
        resource_id: Some(Uuid::new_v4().to_string()),
    }
}

/// Create a simple policy (no conditions).
fn create_simple_policy(id: Uuid, tenant_id: Uuid, effect: &str) -> PolicyWithConditions {
    PolicyWithConditions {
        id,
        tenant_id,
        name: format!("policy-{}", id),
        effect: effect.to_string(),
        priority: 100,
        status: "active".to_string(),
        resource_type: Some("document".to_string()),
        action: Some("read".to_string()),
        conditions: vec![],
    }
}

/// Create a policy with conditions.
fn create_policy_with_conditions(
    id: Uuid,
    tenant_id: Uuid,
    effect: &str,
    num_conditions: usize,
) -> PolicyWithConditions {
    let conditions: Vec<ConditionData> = (0..num_conditions)
        .map(|i| ConditionData {
            id: Uuid::new_v4(),
            condition_type: "user_attribute".to_string(),
            attribute_path: Some(format!("attributes.field{}", i)),
            operator: Some("equals".to_string()),
            value: json!({"expected": format!("value{}", i)}),
        })
        .collect();

    PolicyWithConditions {
        id,
        tenant_id,
        name: format!("policy-{}", id),
        effect: effect.to_string(),
        priority: 100,
        status: "active".to_string(),
        resource_type: Some("document".to_string()),
        action: Some("read".to_string()),
        conditions,
    }
}

/// Create user attributes that match the conditions.
fn create_matching_attributes(num_fields: usize) -> serde_json::Value {
    let mut attrs = serde_json::Map::new();
    for i in 0..num_fields {
        attrs.insert(format!("field{}", i), json!(format!("value{}", i)));
    }
    json!({ "attributes": attrs })
}

/// Benchmark simple policy evaluation (1-3 rules, no conditions).
fn bench_simple_policy(c: &mut Criterion) {
    let tenant_id = Uuid::new_v4();
    let policies: Vec<PolicyWithConditions> = (0..3)
        .map(|i| {
            create_simple_policy(
                Uuid::new_v4(),
                tenant_id,
                if i == 2 { "allow" } else { "deny" },
            )
        })
        .collect();

    let request = create_request();

    c.bench_function("policy_eval_simple_3_rules", |b| {
        b.iter(|| {
            PolicyEvaluator::evaluate_policies(
                black_box(&policies),
                black_box(&request),
                black_box(None),
                black_box(None),
            )
        })
    });
}

/// Benchmark medium policy evaluation (4-9 rules with conditions).
fn bench_medium_policy(c: &mut Criterion) {
    let tenant_id = Uuid::new_v4();
    let policies: Vec<PolicyWithConditions> = (0..6)
        .map(|i| {
            create_policy_with_conditions(
                Uuid::new_v4(),
                tenant_id,
                if i == 5 { "allow" } else { "deny" },
                2, // 2 conditions per policy
            )
        })
        .collect();

    let request = create_request();
    let attrs = create_matching_attributes(2);

    c.bench_function("policy_eval_medium_6_rules_12_conditions", |b| {
        b.iter(|| {
            PolicyEvaluator::evaluate_policies(
                black_box(&policies),
                black_box(&request),
                black_box(Some(&attrs)),
                black_box(None),
            )
        })
    });
}

/// Benchmark complex policy evaluation (10+ rules with many conditions).
fn bench_complex_policy(c: &mut Criterion) {
    let tenant_id = Uuid::new_v4();
    let policies: Vec<PolicyWithConditions> = (0..15)
        .map(|i| {
            create_policy_with_conditions(
                Uuid::new_v4(),
                tenant_id,
                if i == 14 { "allow" } else { "deny" },
                5, // 5 conditions per policy
            )
        })
        .collect();

    let request = create_request();
    let attrs = create_matching_attributes(5);

    c.bench_function("policy_eval_complex_15_rules_75_conditions", |b| {
        b.iter(|| {
            PolicyEvaluator::evaluate_policies(
                black_box(&policies),
                black_box(&request),
                black_box(Some(&attrs)),
                black_box(None),
            )
        })
    });
}

/// Benchmark worst-case scenario (all policies evaluated, no match).
fn bench_worst_case(c: &mut Criterion) {
    let tenant_id = Uuid::new_v4();
    // Create policies that won't match the request
    let policies: Vec<PolicyWithConditions> = (0..20)
        .map(|_| {
            let mut policy = create_policy_with_conditions(Uuid::new_v4(), tenant_id, "deny", 3);
            // Make policy not match by changing resource type
            policy.resource_type = Some("other_resource".to_string());
            policy
        })
        .collect();

    let request = create_request();
    let attrs = create_matching_attributes(3);

    c.bench_function("policy_eval_worst_case_20_rules_no_match", |b| {
        b.iter(|| {
            PolicyEvaluator::evaluate_policies(
                black_box(&policies),
                black_box(&request),
                black_box(Some(&attrs)),
                black_box(None),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_simple_policy,
    bench_medium_policy,
    bench_complex_policy,
    bench_worst_case,
);
criterion_main!(benches);
