//! Closed schema-1.0 fixture metadata, never canonical expressions or host authority.

use super::{exact_keys, string_at, text, Result, EVENTS, MAX_INT, MAX_NODES, STATUSES};
use serde_json::{json, Value};

fn reference(value: &Value, key: &str) -> Result<()> {
    let value = string_at(value, key)?;
    text(value)?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("metadata reference must be nonempty safe text".into());
    }
    Ok(())
}

fn digest(value: &Value, key: &str) -> Result<()> {
    let value = string_at(value, key)?;
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("metadata digest must be SHA256".into());
    }
    Ok(())
}

fn uuid(value: &Value, key: &str) -> Result<()> {
    let value = string_at(value, key)?;
    if value.len() != 36 || !value.bytes().enumerate().all(|(i, b)| {
        if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() }
    }) {
        return Err("metadata identity must be UUID".into());
    }
    Ok(())
}

fn counter(value: &Value, key: &str) -> Result<()> {
    if !value[key].as_i64().is_some_and(|n| (0..=MAX_INT).contains(&n)) {
        return Err("metadata counter outside exact nonnegative int53".into());
    }
    Ok(())
}

fn identifiers(value: &Value, key: &str) -> Result<()> {
    let entries = value[key].as_array().ok_or("metadata identifier list required")?;
    if entries.len() > MAX_NODES {
        return Err("metadata identifier list exceeds existing node budget".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in entries {
        let id = entry.as_str().ok_or("metadata identifier must be string")?;
        text(id)?;
        if id.is_empty() || id.chars().any(char::is_control) || !seen.insert(id) {
            return Err("metadata identifiers must be safe and unique".into());
        }
    }
    Ok(())
}

fn disposition(value: &Value, key: &str) -> Result<()> {
    if !STATUSES.contains(&string_at(value, key)?) {
        return Err("metadata disposition outside closed enum".into());
    }
    Ok(())
}

pub(super) fn is_complete_shape(event: &Value) -> bool {
    event.as_object().is_some_and(|map| {
        map.keys().any(|key| !["kind", "expected_revision", "payload"].contains(&key.as_str()))
    })
}

pub(super) fn project(event: &Value) -> Result<Value> {
    let kind = string_at(event, "kind")?;
    if !EVENTS.contains(&kind) {
        return Err("metadata event kind outside closed schema".into());
    }
    let namespace = match (event.get("operation_id"), event.get("install_id")) {
        (Some(_), None) => "operation_id",
        (None, Some(_)) => "install_id",
        _ => return Err("metadata requires exactly one event namespace".into()),
    };
    if matches!(kind, "InstallConsented" | "CandidateVerified" | "Activated")
        && namespace != "install_id"
        || matches!(kind, "OperationRequested" | "Observed" | "ApplyConsented")
            && namespace != "operation_id"
    {
        return Err("metadata event namespace does not match kind".into());
    }
    exact_keys(event, &[
        "schema", "event_id", namespace, "kind", "expected_revision",
        "plan_digest", "context_digest", "policy_digest", "target_id", "step_id", "payload",
    ])?;
    if string_at(event, "schema")? != "1.0" {
        return Err("metadata event schema must be 1.0".into());
    }
    uuid(event, "event_id")?;
    uuid(event, namespace)?;
    counter(event, "expected_revision")?;
    for key in ["plan_digest", "context_digest", "policy_digest"] { digest(event, key)?; }
    for key in ["target_id", "step_id"] { reference(event, key)?; }
    let payload = &event["payload"];
    match kind {
        "OperationRequested" => {
            exact_keys(payload, &["request_digest", "loaded_input_digest", "plan_digest", "mode"])?;
            for key in ["request_digest", "loaded_input_digest", "plan_digest"] { digest(payload, key)?; }
            if !["preview", "check", "observe", "output", "apply", "rollback"]
                .contains(&string_at(payload, "mode")?) {
                return Err("metadata request mode outside closed enum".into());
            }
            if payload["plan_digest"] != event["plan_digest"] {
                return Err("metadata request plan digest mismatch".into());
            }
        }
        "DependencyObserved" => {
            exact_keys(payload, &["dependency_id", "context_digest", "probe_receipt", "probe_digest", "readiness"])?;
            reference(payload, "dependency_id")?;
            reference(payload, "probe_receipt")?;
            digest(payload, "context_digest")?;
            digest(payload, "probe_digest")?;
            if payload["context_digest"] != event["context_digest"]
                || !["ready", "blocked", "unsupported"].contains(&string_at(payload, "readiness")?) {
                return Err("metadata dependency identity or readiness mismatch".into());
            }
        }
        "InstallConsented" => {
            exact_keys(payload, &["lifecycle_kind", "plan_id", "lifecycle_binding_digest", "private_consent_reference"])?;
            if !["install", "uninstall", "restore"].contains(&string_at(payload, "lifecycle_kind")?) {
                return Err("metadata lifecycle kind outside closed enum".into());
            }
            uuid(payload, "plan_id")?;
            digest(payload, "lifecycle_binding_digest")?;
            reference(payload, "private_consent_reference")?;
            if payload["lifecycle_kind"] != "install" && payload["plan_id"] != event["install_id"] {
                return Err("metadata lifecycle namespace mismatch".into());
            }
        }
        "Observed" => {
            exact_keys(payload, &["invocation_id", "target_id", "step_id", "observation_ref", "observation_digest", "disposition"])?;
            for key in ["invocation_id", "target_id", "step_id", "observation_ref"] { reference(payload, key)?; }
            digest(payload, "observation_digest")?;
            disposition(payload, "disposition")?;
        }
        "ApplyConsented" => {
            exact_keys(payload, &["plan_digest", "approved_effect_ids", "approved_recovery_ids", "private_consent_reference"])?;
            digest(payload, "plan_digest")?;
            identifiers(payload, "approved_effect_ids")?;
            identifiers(payload, "approved_recovery_ids")?;
            reference(payload, "private_consent_reference")?;
            if payload["plan_digest"] != event["plan_digest"] {
                return Err("metadata approved plan digest mismatch".into());
            }
        }
        "StepCompleted" => {
            exact_keys(payload, &["invocation_id", "effect_id", "target_id", "step_id", "safe_result_digest", "primary", "cleanup", "remote_uncertain"])?;
            for key in ["invocation_id", "effect_id", "target_id", "step_id"] { reference(payload, key)?; }
            digest(payload, "safe_result_digest")?;
            disposition(payload, "primary")?;
            disposition(payload, "cleanup")?;
            if !payload["remote_uncertain"].is_boolean() {
                return Err("metadata remote uncertainty requires bool".into());
            }
        }
        "CandidateVerified" => {
            exact_keys(payload, &["candidate_digest", "registry_digest", "assets_digest", "policy_digest", "qualification_digest", "functional_evidence_ref"])?;
            for key in ["candidate_digest", "registry_digest", "assets_digest", "policy_digest", "qualification_digest"] { digest(payload, key)?; }
            reference(payload, "functional_evidence_ref")?;
            if payload["policy_digest"] != event["policy_digest"] {
                return Err("metadata candidate policy digest mismatch".into());
            }
        }
        "Activated" => {
            exact_keys(payload, &["expected_pointer_digest", "current_pointer_digest", "new_pointer_digest", "cas_receipt"])?;
            for key in ["expected_pointer_digest", "current_pointer_digest", "new_pointer_digest"] { digest(payload, key)?; }
            reference(payload, "cas_receipt")?;
            if payload["expected_pointer_digest"] != payload["current_pointer_digest"] {
                return Err("metadata activation expected pointer mismatch".into());
            }
        }
        "Cancelled" => {
            exact_keys(payload, &["accepted_host_receipt", "revocation_revision", "safe_reason"])?;
            reference(payload, "accepted_host_receipt")?;
            reference(payload, "safe_reason")?;
            counter(payload, "revocation_revision")?;
        }
        _ => return Err("metadata event kind outside closed schema".into()),
    }
    if matches!(kind, "Observed" | "StepCompleted")
        && (payload["target_id"] != event["target_id"] || payload["step_id"] != event["step_id"]) {
        return Err("metadata completion target or step mismatch".into());
    }
    let mut projected = json!({"kind":kind,"expected_revision":event["expected_revision"]});
    if kind == "InstallConsented" {
        projected["payload"] = json!({"lifecycle_kind":payload["lifecycle_kind"]});
    }
    Ok(projected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{contract_data, Budget};
    use px_ast::Statement;

    fn authored_events() -> Vec<Value> {
        let document = px_compiler::parse(include_str!(
            "../../../netops/ansible/policy/ansible_molecule.contracts.px"
        )).expect("current authored contracts parse");
        document.statements.iter().flat_map(|statement| match statement {
            Statement::Contract(contract) => contract.examples.iter().map(|example| {
                contract_data(&example.input, &mut vec!["input".into()], &mut Budget::default())
                    .expect("current contract data")["event"].clone()
            }).collect::<Vec<_>>(),
            _ => panic!("only contract declarations"),
        }).filter(is_complete_shape).collect()
    }

    #[test]
    fn complete_metadata_retains_nine_authored_variants_but_no_expression_authority() {
        let events = authored_events();
        assert_eq!(events.len(), 45);
        let kinds = events.iter().map(|event| event["kind"].as_str().expect("kind"))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(kinds.len(), 9);
        for event in events {
            let original = event.clone();
            let projected = project(&event).expect("closed full metadata");
            assert_eq!(event, original);
            assert_eq!(projected["kind"], event["kind"]);
            assert_eq!(projected["expected_revision"], event["expected_revision"]);
            assert!(projected.get("event_id").is_none());
            assert!(projected.get("plan_digest").is_none());
            assert!(projected.get("private_consent_reference").is_none());
            if event["kind"] == "InstallConsented" {
                exact_keys(&projected, &["kind", "expected_revision", "payload"]).unwrap();
                exact_keys(&projected["payload"], &["lifecycle_kind"]).unwrap();
            } else {
                exact_keys(&projected, &["kind", "expected_revision"]).unwrap();
            }
        }
    }

    #[test]
    fn full_metadata_rejects_each_missing_common_or_payload_field_and_unknown_keys() {
        for event in authored_events() {
            for key in event.as_object().unwrap().keys() {
                let mut missing = event.clone();
                missing.as_object_mut().unwrap().remove(key);
                assert!(project(&missing).is_err(), "missing common field {key}");
            }
            for key in event["payload"].as_object().unwrap().keys() {
                let mut missing = event.clone();
                missing["payload"].as_object_mut().unwrap().remove(key);
                assert!(project(&missing).is_err(), "missing payload field {key}");
            }
            let mut extra = event.clone();
            extra["payload"]["allow"] = json!(true);
            assert!(project(&extra).is_err());
            extra = event.clone();
            extra["permission"] = json!(true);
            assert!(project(&extra).is_err());
        }
    }

    #[test]
    fn full_metadata_rejects_schema_namespace_domain_and_reference_substitution() {
        let event = authored_events().into_iter()
            .find(|event| event["kind"] == "OperationRequested").unwrap();
        for (key, value) in [
            ("schema", json!("2.0")), ("expected_revision", json!(true)),
            ("expected_revision", json!(MAX_INT + 1)), ("expected_revision", json!(-1)),
            ("event_id", json!("not-uuid")), ("context_digest", json!("not-digest")),
            ("target_id", json!("")), ("step_id", json!("unsafe\nreference")),
        ] {
            let mut invalid = event.clone();
            invalid[key] = value;
            assert!(project(&invalid).is_err(), "invalid {key}");
        }
        let mut invalid = event.clone();
        invalid["install_id"] = invalid["operation_id"].clone();
        assert!(project(&invalid).is_err());
        invalid = event.clone();
        invalid["payload"]["plan_digest"] = json!("e".repeat(64));
        assert!(project(&invalid).is_err());
        let mut dependency = authored_events().into_iter()
            .find(|event| event["kind"] == "DependencyObserved").unwrap();
        let identity = dependency.as_object_mut().unwrap().remove("install_id").unwrap();
        dependency["operation_id"] = identity;
        assert!(project(&dependency).is_ok(), "dependency observations can precede operational work");
    }

    #[test]
    fn full_metadata_rejects_completion_identity_drift_and_duplicate_approved_ids() {
        for event in authored_events() {
            if matches!(event["kind"].as_str(), Some("Observed" | "StepCompleted")) {
                for key in ["target_id", "step_id"] {
                    let mut invalid = event.clone();
                    invalid["payload"][key] = json!("different-safe-reference");
                    assert!(project(&invalid).is_err());
                }
            }
            if event["kind"] == "ApplyConsented" {
                let mut invalid = event.clone();
                invalid["payload"]["approved_effect_ids"] = json!(["apply-0", "apply-0"]);
                assert!(project(&invalid).is_err());
            }
        }
    }
}
