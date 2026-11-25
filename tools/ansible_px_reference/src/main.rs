//! ORIGINAL consumer draft. Build-only, uncompiled and unqualified.
//! Canonical APIs/pin: retained pinned-prerequisite-inspection.md, not a Python ABI.
//! No network, installation, host effects, application predicates or runtime fallback.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use px_ast::{BinOp, Expr, PxDocument, Severity, Statement, UnaryOp, Value as AstValue};
use px_eval::{eval_constraint, eval_rule, evaluate_expr, ConstraintOutcome, EmptyRegistry};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod event_metadata;
mod parse_budget;

const REVISION: &str = "6d367fe673756dabaa6085bc6b5202debaaabe6f";
const PROFILE: &str = "netops-reference-v1";
const NUMERIC_PROFILE: &str = "exact-int53-finite-order-v1";
const MAX_INT: i64 = 9_007_199_254_740_991;
const MAX_BYTES: usize = 1_048_576;
const MAX_DECLARATIONS: usize = 512;
const MAX_NODES: usize = 32_768;
const MAX_DEPTH: usize = 32;
const MAX_VISITS: usize = 200_000;
const MAX_STRING: usize = 4096;
const PREFIX: &str = "netops_companion_";
const PHASES: &[&str] = &[
    "Planned", "Staging", "Verified", "Active", "Observing", "Admitted", "Executing",
    "Cancelling", "Completed", "Cancelled", "Uncertain",
];
const STATUSES: &[&str] = &["success", "partial", "failed", "cancelled", "unsupported", "blocked"];
const EVENTS: &[&str] = &[
    "OperationRequested", "DependencyObserved", "InstallConsented", "Observed",
    "ApplyConsented", "StepCompleted", "CandidateVerified", "Activated", "Cancelled",
];
const LIFECYCLE_EFFECTS: &[&str] = &[
    "dependency-probe", "dependency-download", "dependency-stage", "dependency-verify",
    "dependency-activate", "dependency-uninstall", "restore-active-pointer",
];

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Type {
    Bool,
    Int,
    Float,
    String,
}

#[derive(Default)]
struct Budget {
    nodes: usize,
    visits: usize,
}

impl Budget {
    fn enter(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err("policy AST budget exceeded".into());
        }
        Ok(())
    }

    fn visit(&mut self, amount: usize) -> Result<()> {
        self.visits = self.visits.checked_add(amount).ok_or("visit overflow")?;
        if self.visits > MAX_VISITS {
            return Err("canonical evaluation visit budget exceeded".into());
        }
        Ok(())
    }
}

fn text(value: &str) -> Result<()> {
    if value.len() > MAX_STRING {
        return Err("string exceeds profile".into());
    }
    Ok(())
}

fn logical(name: &str) -> Result<String> {
    let tail = name.strip_prefix(PREFIX).ok_or("unknown declaration prefix")?;
    if tail.is_empty() || !tail.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return Err("invalid declaration name".into());
    }
    let invariant = [
        "input_binding", "identity", "ownership", "mode", "consent", "route",
        "credential_channel", "source_integrity", "pre_state", "recovery",
        "cancellation", "output_safety", "consequential",
    ].iter().any(|reason| tail == format!("invariant_{reason}"));
    let family = [
        "catalog", "dependency_readiness", "setup_consent", "candidate_lifecycle",
        "scan", "inventory", "vault", "config_collect", "config_mutate", "recovery",
        "health", "compare", "report", "aggregate", "cancel_control", "qualification",
    ].iter().any(|family| tail.starts_with(format!("{family}_").as_str()));
    if !invariant && !family { return Err("unknown rule family or invariant".into()); }
    Ok(format!("netops.companion.{tail}"))
}

fn scalar(value: &AstValue) -> Result<(Type, Value)> {
    match value {
        AstValue::Boolean(v) => Ok((Type::Bool, json!(v))),
        AstValue::Integer(v) if (-MAX_INT..=MAX_INT).contains(v) => Ok((Type::Int, json!(v))),
        AstValue::Float(v) if v.is_finite() => Ok((Type::Float, json!(v))),
        AstValue::String(v) => {
            text(v)?;
            Ok((Type::String, json!(v)))
        }
        _ => Err("unsupported scalar or numeric domain".into()),
    }
}

fn field_type(path: &[String]) -> Result<Type> {
    let borrowed: Vec<&str> = path.iter().map(String::as_str).collect();
    match borrowed.as_slice() {
        ["event", "kind"] | ["event", "payload", "lifecycle_kind"]
        | ["state", "phase"] | ["request", "area"] | ["request", "operation"]
        | ["request", "mode"] | ["config", "mode"]
        | ["readiness", "native" | "companion" | "enhanced"]
        | ["lifecycle", "next_effect_kind"] | ["operational", "next_effect_kind"] => Ok(Type::String),
        ["state", "revision"] | ["event", "expected_revision"]
        | ["scope", "selected_count"] | ["control", "remaining_ms"]
        | ["consent", "remaining_ms"]
        | ["result", "selected" | "completed" | "unsuccessful" | "failed" | "cancelled" | "unsupported" | "blocked"] => Ok(Type::Int),
        ["health", "reading" | "threshold"] => Ok(Type::Float),
        ["binding", "input_valid" | "plan_current" | "policy_current"]
        | ["scope", "exclusions_valid"] | ["config", "enabled"] | ["control", "cancelled"]
        | ["readiness", "selected_complete"] | ["controller", "qualified"]
        | ["route", "qualified"] | ["credentials", "channel_qualified"]
        | ["ownership", "valid"] | ["storage", "sensitive_ready"]
        | ["output", "retention_requested" | "git_requested"]
        | ["consent", "present" | "binding_matches" | "effects_match" | "recovery_matches"]
        | ["consequential", "required" | "granted"]
        | ["result", "policy_failed" | "cleanup_failed" | "remote_uncertain"]
        | ["inventory", "source_valid" | "cache_binding_valid" | "hostvars_safe"]
        | ["discovery", "scope_valid"]
        | ["change", "prestate_bound" | "vendor_recovery_qualified" | "poststate_verified"]
        | ["health", "reading_present" | "reading_finite" | "check_supported"]
        | ["compare", "inputs_bound" | "vendor_supported"]
        | ["report", "coverage_complete" | "pdf_ready" | "output_safe"]
        | ["candidate", "verified" | "pointer_matches" | "retained_owned"] => Ok(Type::Bool),
        _ => Err("path is not an exact typed feature fact".into()),
    }
}

fn literal(ty: Type, value: Value) -> Value {
    let name = match ty {
        Type::Bool => "bool", Type::Int => "int", Type::Float => "float", Type::String => "string",
    };
    json!({"kind":"literal","type":name,"value":value})
}

fn expression(
    expr: &Expr,
    budget: &mut Budget,
    depth: usize,
    paths: &mut BTreeSet<Vec<String>>,
) -> Result<(Type, Value)> {
    budget.enter(depth)?;
    match expr {
        Expr::Literal(value) => {
            let (ty, value) = scalar(value)?;
            Ok((ty, literal(ty, value)))
        }
        Expr::Path(path) => {
            let segments: Vec<String> = path.segments.iter().map(|s| s.name.clone()).collect();
            // Approved exact expression-only keyword exception, before fact lookup.
            if segments.len() == 1 && (segments[0] == "true" || segments[0] == "false") {
                return Ok((Type::Bool, literal(Type::Bool, json!(segments[0] == "true"))));
            }
            let ty = field_type(&segments)?;
            paths.insert(segments.clone());
            Ok((ty, json!({"kind":"path","segments":segments})))
        }
        Expr::Paren(inner) => {
            let (ty, inner) = expression(inner, budget, depth + 1, paths)?;
            Ok((ty, json!({"kind":"paren","operand":inner})))
        }
        Expr::Unary { op: UnaryOp::Not, operand } => {
            let (ty, inner) = expression(operand, budget, depth + 1, paths)?;
            if ty != Type::Bool { return Err("not requires exact bool".into()); }
            Ok((Type::Bool, json!({"kind":"not","operand":inner})))
        }
        Expr::Unary { op: UnaryOp::Neg, operand } => {
            // Only the pinned parser's numeric literal constant shape is normalized.
            budget.enter(depth + 1)?;
            let (ty, value) = match operand.as_ref() {
                Expr::Literal(AstValue::Integer(value)) if (-MAX_INT..=MAX_INT).contains(value) => {
                    let negated = value.checked_neg().ok_or("integer negation overflow")?;
                    (Type::Int, json!(negated))
                }
                Expr::Literal(AstValue::Float(value)) if value.is_finite() => {
                    (Type::Float, json!(-value))
                }
                _ => return Err("negation requires an in-profile numeric literal constant".into()),
            };
            Ok((ty, literal(ty, value)))
        }
        Expr::Binary { left, op, right } => {
            // Validate BOTH branches, including unreachable short-circuit operands.
            let (lt, left) = expression(left, budget, depth + 1, paths)?;
            let (rt, right) = expression(right, budget, depth + 1, paths)?;
            if lt != rt { return Err("mixed comparison domains".into()); }
            let name = match op {
                BinOp::And | BinOp::Or if lt == Type::Bool => {
                    if matches!(op, BinOp::And) { "And" } else { "Or" }
                }
                BinOp::Eq | BinOp::Neq if lt != Type::Float => {
                    if matches!(op, BinOp::Eq) { "Eq" } else { "Neq" }
                }
                BinOp::Gt | BinOp::Lt | BinOp::Gte | BinOp::Lte
                    if lt == Type::Int || lt == Type::Float => match op {
                        BinOp::Gt => "Gt", BinOp::Lt => "Lt", BinOp::Gte => "Gte", _ => "Lte",
                    },
                _ => return Err("operator/type pair outside numeric profile".into()),
            };
            Ok((Type::Bool, json!({"kind":"binary","op":name,"left":left,"right":right})))
        }
        _ => Err("unsupported expression; no calls, vars, arithmetic or executable constructs".into()),
    }
}

fn boolean(expr: &Expr, budget: &mut Budget, paths: &mut BTreeSet<Vec<String>>) -> Result<Value> {
    let (ty, projected) = expression(expr, budget, 0, paths)?;
    if ty != Type::Bool { return Err("condition must have exact bool type".into()); }
    Ok(projected)
}

fn nullable_contract_leaf(path: &[String]) -> bool {
    path.len() == 2 && path[0] == "expect"
        && matches!(path[1].as_str(), "reason" | "next_phase" | "aggregate" | "error")
}

fn contract_data(value: &AstValue, path: &mut Vec<String>, budget: &mut Budget) -> Result<Value> {
    budget.enter(path.len())?;
    match value {
        AstValue::Map(entries) => {
            let mut out = serde_json::Map::new();
            for (key, value) in entries {
                text(&key.name)?;
                if out.contains_key(&key.name) { return Err("duplicate contract map key".into()); }
                path.push(key.name.clone());
                let converted = contract_data(value, path, budget)?;
                path.pop();
                out.insert(key.name.clone(), converted);
            }
            Ok(Value::Object(out))
        }
        AstValue::List(entries) => {
            let mut out = Vec::new();
            for (index, value) in entries.iter().enumerate() {
                path.push(index.to_string());
                out.push(contract_data(value, path, budget)?);
                path.pop();
            }
            Ok(Value::Array(out))
        }
        AstValue::Path(p)
            if p.segments.len() == 1 && p.segments[0].name == "null"
                && nullable_contract_leaf(path) => Ok(Value::Null),
        AstValue::Path(_) | AstValue::Ident(_) | AstValue::Paren(_) => {
            Err("contract path/identifier/expression outside exact nullable-leaf exception".into())
        }
        _ => scalar(value).map(|(_, v)| v),
    }
}

fn exact_keys(value: &Value, required: &[&str]) -> Result<()> {
    let map = value.as_object().ok_or("expected closed object")?;
    if map.len() != required.len() || required.iter().any(|key| !map.contains_key(*key)) {
        return Err("missing or extra contract field".into());
    }
    Ok(())
}

fn string_at<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| format!("string field required: {key}"))
}

fn action(name: &str, params: &[(String, Value)]) -> Result<Value> {
    if params.len() != 1 { return Err("action requires one constant parameter".into()); }
    let (key, value) = &params[0];
    let value = value.as_str().ok_or("action parameter must be literal string")?;
    let valid = match (name, key.as_str()) {
        ("set_phase", "phase") => PHASES.contains(&value),
        ("record_step", "disposition") | ("record_outcome", "status") => STATUSES.contains(&value),
        ("revoke_pending", "scope") => value == "operation",
        ("request_effect", "kind") => LIFECYCLE_EFFECTS.contains(&value) || [
            "scan", "save", "export", "refresh", "resolve-for-run", "gather",
            "collect", "backup", "apply", "rollback", "render", "retention", "git",
        ].contains(&value),
        _ => false,
    };
    if !valid { return Err("unknown static action or constant parameter".into()); }
    let mut object = serde_json::Map::new();
    object.insert(key.clone(), json!(value));
    Ok(json!({"name":name,"params":object}))
}

struct Program {
    source: PxDocument,
    projected: Vec<Value>,
    manifest: BTreeMap<String, BTreeSet<Vec<String>>>,
    rules: BTreeSet<String>,
    constraints: BTreeSet<String>,
    nodes: usize,
}

fn project(source: PxDocument) -> Result<Program> {
    if source.statements.len() > MAX_DECLARATIONS { return Err("declaration budget".into()); }
    let mut budget = Budget::default();
    let mut projected = Vec::new();
    let mut manifest = BTreeMap::new();
    let mut rules = BTreeSet::new();
    let mut constraints = BTreeSet::new();
    for (order, statement) in source.statements.iter().enumerate() {
        let mut paths = BTreeSet::new();
        let declaration = (|| -> Result<(String, Value)> { Ok(match statement {
            Statement::Rule(rule) => {
                if rule.priority.unwrap_or(0) != 0 || !rule.let_bindings.is_empty()
                    || !rule.captures.is_empty() || rule.conditions.is_empty() || rule.actions.is_empty() {
                    return Err("rule shape outside profile".into());
                }
                let conditions: Vec<Value> = rule.conditions.iter()
                    .map(|expr| boolean(expr, &mut budget, &mut paths)).collect::<Result<_>>()?;
                if !paths.contains(&vec!["event".into(), "kind".into()]) {
                    return Err("rule lacks explicit event-kind guard".into());
                }
                let mut actions = Vec::new();
                let mut action_keys = BTreeSet::new();
                let mut transitions = 0;
                for item in &rule.actions {
                    if item.condition.is_some() { return Err("conditional action outside profile".into()); }
                    let mut keys = BTreeSet::new();
                    let mut params = Vec::new();
                    for pair in &item.params {
                        if !keys.insert(pair.key.name.clone()) { return Err("duplicate parameter".into()); }
                        params.push((pair.key.name.clone(), scalar(&pair.value)?.1));
                    }
                    let value = action(&item.action_name.name, &params)?;
                    if !action_keys.insert(serde_json::to_string(&value).map_err(|_| "action encoding")?) {
                        return Err("duplicate action occurrence in declaration".into());
                    }
                    if item.action_name.name == "set_phase" { transitions += 1; }
                    actions.push(value);
                }
                if transitions > 1 { return Err("conflicting transitions".into()); }
                rules.insert(rule.name.name.clone());
                (rule.name.name.clone(), json!({
                    "kind":"rule","id":logical(&rule.name.name)?,"source_id":rule.name.name,
                    "order":order,"conditions":conditions,"actions":actions
                }))
            }
            Statement::Constraint(c) => {
                if !matches!(c.severity, Severity::Error) || c.when.is_none() || c.require.is_none() {
                    return Err("constraint metadata outside closed profile".into());
                }
                // Inspect canonical serde fields without inventing an unretained Rust field name.
                let metadata = serde_json::to_value(c).map_err(|_| "constraint metadata encoding")?;
                for (key, value) in metadata.as_object().ok_or("constraint metadata object")? {
                    if !["name", "when", "require", "severity", "message", "span"].contains(&key.as_str())
                        && !value.is_null() && value.as_array().is_none_or(|v| !v.is_empty()) {
                        return Err("unsupported nonempty constraint metadata".into());
                    }
                }
                let message = metadata.get("message").ok_or("constraint reason required")?;
                let message = message.as_str().or_else(|| message.get("value").and_then(Value::as_str))
                    .ok_or("canonical constraint reason is not constant text")?;
                text(message)?;
                let guard = boolean(c.when.as_ref().ok_or("guard required")?, &mut budget, &mut paths)?;
                let require = boolean(c.require.as_ref().ok_or("require required")?, &mut budget, &mut paths)?;
                constraints.insert(c.name.name.clone());
                (c.name.name.clone(), json!({
                    "kind":"constraint","id":logical(&c.name.name)?,"source_id":c.name.name,
                    "guard":guard,"require":require,"severity":"error","reason":message
                }))
            }
            _ => return Err("source contains unsupported declaration".into()),
        }) })().map_err(|error| format!("source-project declaration={order}: {error}"))?;
        let (name, value) = declaration;
        if manifest.insert(name, paths).is_some() { return Err("duplicate declaration".into()); }
        projected.push(value);
    }
    Ok(Program { source, projected, manifest, rules, constraints, nodes: budget.nodes })
}

fn validate_leaf(path: &[String], value: &Value) -> Result<()> {
    let ty = field_type(path)?;
    let valid = match ty {
        Type::Bool => value.is_boolean(),
        Type::Int => value.as_i64().is_some_and(|n| (-MAX_INT..=MAX_INT).contains(&n)),
        Type::Float => value.is_f64() && value.as_f64().is_some_and(f64::is_finite),
        Type::String => value.as_str().is_some_and(|s| s.len() <= MAX_STRING),
    };
    if !valid { return Err("fact type/domain mismatch".into()); }
    if ty == Type::Int && value.as_i64().is_some_and(|n| n < 0) {
        return Err("counter/revision/deadline fact is negative".into());
    }
    let borrowed: Vec<&str> = path.iter().map(String::as_str).collect();
    if let Some(s) = value.as_str() {
        let valid = match borrowed.as_slice() {
            ["event", "kind"] => EVENTS.contains(&s),
            ["event", "payload", "lifecycle_kind"] => ["install", "uninstall", "restore"].contains(&s),
            ["state", "phase"] => PHASES.contains(&s),
            ["request", "area"] => ["scan", "inventory", "vault", "config", "health", "compare", "report", "setup"].contains(&s),
            ["request", "mode"] => ["preview", "check", "observe", "output", "apply", "rollback"].contains(&s),
            ["request", "operation"] => [
                "discover", "inventory-preview", "save", "validate", "export", "refresh",
                "preflight", "resolve-for-run", "collect", "backup", "plan", "apply", "rollback",
                "gather", "evaluate", "compare", "remediation-preview", "generate", "aggregate", "render",
                "install", "uninstall", "restore",
            ].contains(&s),
            ["config", "mode"] => ["audit", "enforce"].contains(&s),
            ["readiness", "native" | "companion" | "enhanced"] => ["ready", "blocked", "unsupported", "not-requested"].contains(&s),
            ["lifecycle", "next_effect_kind"] => s == "none" || LIFECYCLE_EFFECTS.contains(&s),
            ["operational", "next_effect_kind"] => ["none", "collect", "backup", "retention", "git"].contains(&s),
            _ => true,
        };
        if !valid { return Err("fact enum outside closed schema".into()); }
    }
    Ok(())
}

fn validate_tree(value: &Value, path: &mut Vec<String>) -> Result<()> {
    if let Some(map) = value.as_object() {
        if map.is_empty() { return Err("empty fact object".into()); }
        for (key, value) in map {
            path.push(key.clone());
            validate_tree(value, path)?;
            path.pop();
        }
        Ok(())
    } else {
        validate_leaf(path, value)
    }
}

fn lookup<'a>(vars: &'a HashMap<String, Value>, path: &[String]) -> Result<&'a Value> {
    let (first, rest) = path.split_first().ok_or("empty fact path")?;
    let mut value = vars.get(first).ok_or("missing fact root")?;
    for segment in rest { value = value.get(segment).ok_or("missing required fact")?; }
    Ok(value)
}

fn event_variables(event: &Value) -> Result<Value> {
    if event_metadata::is_complete_shape(event) {
        let projected = event_metadata::project(event)?;
        validate_tree(&projected, &mut vec!["event".into()])?;
        return Ok(projected);
    }
    let mut projected = event.clone();
    if event["kind"] == "InstallConsented" {
        // A kind-only target-local fixture asserts no lifecycle payload.
        if let Some(payload) = projected.get_mut("payload") {
            exact_keys(payload, &["lifecycle_kind", "plan_id", "lifecycle_binding_digest"])?;
            let plan_id = string_at(payload, "plan_id")?;
            if plan_id.len() != 36 || !plan_id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) { byte == b'-' }
                else { byte.is_ascii_hexdigit() }
            }) {
                return Err("lifecycle plan_id must be UUID".into());
            }
            let binding_digest = string_at(payload, "lifecycle_binding_digest")?;
            if binding_digest.len() != 64
                || !binding_digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("lifecycle binding digest must be SHA256".into());
            }
            // Metadata is retained in authored input, never in canonical fact variables.
            let map = payload.as_object_mut().ok_or("lifecycle payload must be object")?;
            map.remove("plan_id");
            map.remove("lifecycle_binding_digest");
        }
    }
    validate_tree(&projected, &mut vec!["event".into()])?;
    Ok(projected)
}

fn variables(input: &Value, required: &BTreeSet<Vec<String>>) -> Result<HashMap<String, Value>> {
    exact_keys(input, &["state", "event", "facts"])?;
    let mut vars = HashMap::new();
    validate_tree(&input["state"], &mut vec!["state".into()])?;
    vars.insert("state".into(), input["state"].clone());
    vars.insert("event".into(), event_variables(&input["event"])?);
    let facts = input["facts"].as_object().ok_or("facts must be object")?;
    for (key, value) in facts {
        if vars.contains_key(key) { return Err("facts cannot override event/state".into()); }
        validate_tree(value, &mut vec![key.clone()])?;
        vars.insert(key.clone(), value.clone());
    }
    for path in required { validate_leaf(path, lookup(&vars, path)?)?; }
    Ok(vars)
}

fn source_excludes_operational_path(
    program: &Program, vars: &HashMap<String, Value>, path: &[String],
) -> bool {
    if !matches!(path.first().map(String::as_str), Some("operational" | "output")) {
        return false;
    }
    let owners = program.source.statements.iter().filter_map(|statement| match statement {
        Statement::Rule(rule) if program.manifest.get(&rule.name.name)
            .is_some_and(|paths| paths.contains(path)) => Some(rule),
        _ => None,
    }).collect::<Vec<_>>();
    !owners.is_empty() && owners.iter().all(|rule| {
        for condition in &rule.conditions {
            match evaluate_expr(condition, vars, &EmptyRegistry) {
                Ok(Value::Bool(false)) => return true,
                Ok(Value::Bool(true)) => {}
                _ => return false,
            }
        }
        false
    })
}

fn final_counters(input: &Value) -> Result<()> {
    let result = &input["facts"]["result"];
    exact_keys(result, &[
        "selected", "completed", "unsuccessful", "failed", "cancelled", "unsupported",
        "blocked", "policy_failed", "cleanup_failed", "remote_uncertain",
    ])?;
    for (key, value) in result.as_object().ok_or("final result object required")? {
        validate_leaf(&["result".into(), key.clone()], value)?;
    }
    let selected = result["selected"].as_i64().ok_or("selected count required")?;
    for key in ["completed", "unsuccessful", "failed", "cancelled", "unsupported", "blocked"] {
        let count = result[key].as_i64().ok_or("exact final counter required")?;
        if count > selected { return Err("final counter exceeds selected coverage".into()); }
    }
    let completed = result["completed"].as_i64().ok_or("completed count required")?;
    let unsuccessful = result["unsuccessful"].as_i64().ok_or("unsuccessful count required")?;
    if completed.checked_add(unsuccessful) != Some(selected) {
        return Err("incomplete or double-counted final coverage".into());
    }
    // Category counters are not a declared partition; never invent their sum.
    if unsuccessful == 0 && ["failed", "cancelled", "unsupported", "blocked"].iter()
        .any(|key| result[*key].as_i64().is_some_and(|count| count != 0)) {
        return Err("unsuccessful category without unsuccessful selected work".into());
    }
    Ok(())
}

fn combined_oracle(
    program: &Program,
    input: &Value,
    required: &BTreeSet<Vec<String>>,
    budget: &mut Budget,
) -> Result<Value> {
    let vars = variables(input, required)?;
    let mut outcomes = BTreeMap::new();
    let mut violations = Vec::new();
    for statement in &program.source.statements {
        if let Statement::Constraint(c) = statement {
            budget.visit(program.nodes)?;
            let outcome = eval_constraint(c, &vars, &EmptyRegistry)
                .map_err(|_| "combined canonical constraint error")?;
            let status = match outcome {
                ConstraintOutcome::NotApplicable => "not-applicable",
                ConstraintOutcome::Satisfied => "satisfied",
                ConstraintOutcome::Violated { .. } => {
                    violations.push(logical(&c.name.name)?);
                    "violated"
                }
            };
            outcomes.insert(logical(&c.name.name)?, status);
        }
    }
    if !violations.is_empty() {
        return Ok(json!({
            "decision":"deny","rule_ids":[],"actions":[],
            "constraint_outcomes":outcomes,"violations":violations
        }));
    }
    let mut matched = Vec::new();
    let mut actions = Vec::new();
    let mut occurrences = BTreeSet::new();
    let mut transitions = 0;
    let mut outcomes_count = 0;
    let mut steps = 0;
    let mut effect_rules = 0;
    for statement in &program.source.statements {
        if let Statement::Rule(rule) = statement {
            budget.visit(program.nodes)?;
            let firing = eval_rule(rule, &vars, &EmptyRegistry)
                .map_err(|_| "combined canonical rule error")?;
            if !firing.fired { continue; }
            let declaration = program.projected.iter().find(|p| p["source_id"] == rule.name.name)
                .ok_or("combined projected rule missing")?;
            let static_actions = declaration["actions"].as_array().ok_or("combined static actions")?;
            let names = static_actions.iter().map(|a| string_at(a, "name").map(str::to_string))
                .collect::<Result<Vec<_>>>()?;
            if firing.actions != names { return Err("combined canonical action association mismatch".into()); }
            if names.iter().any(|name| name == "request_effect") { effect_rules += 1; }
            if rule.name.name.starts_with("netops_companion_aggregate_") {
                final_counters(input)?;
            }
            matched.push(logical(&rule.name.name)?);
            for value in static_actions {
                if !occurrences.insert(serde_json::to_string(value).map_err(|_| "combined action encoding")?) {
                    return Err("duplicate combined action occurrence".into());
                }
                match string_at(value, "name")? {
                    "set_phase" => transitions += 1,
                    "record_outcome" => outcomes_count += 1,
                    "record_step" => steps += 1,
                    _ => {}
                }
                actions.push(value.clone());
            }
        }
    }
    if transitions > 1 || outcomes_count > 1 || steps > 1 || effect_rules > 1 {
        return Err("conflicting combined transitions or dispositions".into());
    }
    matched.sort();
    Ok(json!({
        "decision":if matched.is_empty() { "deny" } else { "allow" },
        "rule_ids":matched,"actions":actions,"constraint_outcomes":outcomes,"violations":[]
    }))
}

fn expect_action(value: &Value) -> Result<Value> {
    exact_keys(value, &["name", "params"])?;
    let name = string_at(value, "name")?;
    let map = value["params"].as_object().ok_or("expected action params")?;
    let params = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
    action(name, &params)
}

fn oracle(program: &Program, contracts: PxDocument) -> Result<(Vec<Value>, Vec<Value>)> {
    if program.source.statements.len() + contracts.statements.len() > MAX_DECLARATIONS {
        return Err("combined declaration budget".into());
    }
    let mut budget = Budget { nodes: program.nodes, visits: 0 };
    let mut covered = BTreeSet::new();
    let mut cases = BTreeSet::new();
    let mut projected = Vec::new();
    let mut corpus = Vec::new();
    let combined_paths = program.manifest.values().flat_map(|paths| paths.iter().cloned())
        .collect::<BTreeSet<_>>();
    for (contract_index, statement) in contracts.statements.iter().enumerate() {
        (|| -> Result<()> {
        let c = match statement {
            Statement::Contract(c) => c,
            _ => return Err("contracts file contains non-contract declaration".into()),
        };
        if c.threshold.is_some() { return Err("contract threshold outside profile".into()); }
        let target = c.name.name.strip_suffix("_contract").ok_or("contract suffix required")?;
        let required = program.manifest.get(target).ok_or("orphan contract")?;
        if !covered.insert(target.to_string()) { return Err("duplicate rule contract".into()); }
        let mut decisions = BTreeSet::new();
        let mut distinct_inputs = BTreeSet::new();
        for (index, example) in c.examples.iter().enumerate() {
            (|| -> Result<()> {
            budget.visits = 0;
            if example.threshold.is_some() { return Err("example threshold outside profile".into()); }
            let input = contract_data(&example.input, &mut vec!["input".into()], &mut budget)?;
            let mut expect = contract_data(&example.expect, &mut vec!["expect".into()], &mut budget)?;
            exact_keys(&expect, &["decision", "reason", "actions", "next_phase",
                "aggregate", "constraint_outcomes", "error"])?;
            let case_id = format!("{target}_example_{index}");
            if !cases.insert(case_id.clone()) { return Err("duplicate case id".into()); }
            if !distinct_inputs.insert(serde_json::to_string(&input).map_err(|_| "input encoding")?) {
                return Err("duplicate example input is not boundary coverage".into());
            }
            let decision = string_at(&expect, "decision")?;
            if !["allow", "deny", "error"].contains(&decision) { return Err("unknown expected decision".into()); }
            decisions.insert(decision.to_string());
            for key in ["reason", "next_phase", "aggregate", "error"] {
                if !expect[key].is_null() && !expect[key].is_string() {
                    return Err("nullable expected field requires null or string".into());
                }
            }
            if let Some(phase) = expect["next_phase"].as_str() {
                if !PHASES.contains(&phase) { return Err("unknown expected phase".into()); }
            }
            if let Some(status) = expect["aggregate"].as_str() {
                if !STATUSES.contains(&status) { return Err("unknown expected aggregate".into()); }
            }
            let expected_actions = expect["actions"].as_array().ok_or("actions list required")?
                .iter().map(expect_action).collect::<Result<Vec<_>>>()?;
            let vars = variables(&input, required)?;
            if target.starts_with("netops_companion_aggregate_") { final_counters(&input)?; }
            // Sparse target-local fixtures are never silently completed into runtime events.
            let applicable_paths = combined_paths.iter().filter(|path| {
                !(event_metadata::is_complete_shape(&input["event"])
                    && input["event"]["kind"] != "InstallConsented"
                    && path.as_slice() == ["event", "payload", "lifecycle_kind"])
                    && !(lookup(&vars, path).is_err()
                        && source_excludes_operational_path(program, &vars, path))
            }).cloned().collect::<BTreeSet<_>>();
            let combined = if applicable_paths.iter().all(|path| lookup(&vars, path).is_ok()) {
                Some(combined_oracle(program, &input, &applicable_paths, &mut budget)?)
            } else {
                None
            };
            let mut values = Vec::new();
            let mut fired = Vec::new();
            let mut outcomes = BTreeMap::new();
            let mut canonical_reason: Option<String> = None;
            let mut applicable = false;
            let mut violated = false;
            for statement in &program.source.statements {
                match statement {
                    Statement::Rule(rule) if rule.name.name == target => {
                        budget.visit(program.nodes)?;
                        let result = eval_rule(rule, &vars, &EmptyRegistry).map_err(|_| "canonical rule error")?;
                        for expr in &rule.conditions {
                            budget.visit(program.nodes)?;
                            values.push(evaluate_expr(expr, &vars, &EmptyRegistry)
                                .map_err(|_| "canonical expression error")?);
                        }
                        if result.fired {
                            fired = result.actions;
                            applicable = true;
                        }
                    }
                    Statement::Constraint(c) if c.name.name == target => {
                        budget.visit(program.nodes)?;
                        let outcome = eval_constraint(c, &vars, &EmptyRegistry)
                            .map_err(|_| "canonical constraint error")?;
                        let status = match outcome {
                            ConstraintOutcome::NotApplicable => "not-applicable",
                            ConstraintOutcome::Satisfied => { applicable = true; "satisfied" }
                            ConstraintOutcome::Violated { message, .. } => {
                                violated = true;
                                canonical_reason = message;
                                "violated"
                            }
                        };
                        outcomes.insert(target.to_string(), status.to_string());
                        for expr in [c.when.as_ref(), c.require.as_ref()].into_iter().flatten() {
                            budget.visit(program.nodes)?;
                            values.push(evaluate_expr(expr, &vars, &EmptyRegistry)
                                .map_err(|_| "canonical constraint expression error")?);
                        }
                    }
                    _ => {}
                }
            }
            let expected_names = expected_actions.iter().map(|a| string_at(a, "name").map(str::to_string))
                .collect::<Result<Vec<_>>>()?;
            if fired != expected_names { return Err("canonical fired-action expectation mismatch".into()); }
            if !expected_actions.is_empty() {
                let declaration = program.projected.iter().find(|p| p["source_id"] == target)
                    .ok_or("missing projected target")?;
                let actions = declaration["actions"].as_array().ok_or("expected rule actions")?;
                if actions != &expected_actions {
                    return Err("expected ordered actions differ from constant source".into());
                }
            }
            let actual_decision = if violated || !applicable { "deny" } else { "allow" };
            if actual_decision != decision { return Err("target-local canonical decision mismatch".into()); }
            if expect["constraint_outcomes"] != json!(outcomes) {
                return Err("canonical constraint expectation mismatch".into());
            }
            if program.constraints.contains(target) && expect["reason"] != json!(canonical_reason) {
                return Err("canonical constraint reason mismatch".into());
            }
            let logical_outcomes = outcomes.iter().map(|(name, status)| {
                Ok((logical(name)?, status.clone()))
            }).collect::<Result<BTreeMap<_, _>>>()?;
            expect["constraint_outcomes"] = json!(logical_outcomes);
            // Host phase/aggregate/error are authored expectations, NOT canonical effect outputs.
            projected.push(json!({"case_id":case_id,"rule_id":logical(target)?,"input":input,"expect":expect}));
            corpus.push(json!({
                "case_id":case_id,"rule_id":logical(target)?,"input":input,
                "canonical":{"expression_values":values,"fired_actions":fired,
                    "constraint_outcomes":logical_outcomes,"combined":combined},
                "host_expectations":expect
            }));
            Ok(())
            })().map_err(|error| format!("example={index}: {error}"))?;
        }
        if program.rules.contains(target) {
            if c.examples.len() < 3 || !decisions.contains("allow") || !decisions.contains("deny") {
                return Err("rule requires allow, deny and distinct boundary examples".into());
            }
        } else if program.constraints.contains(target) && !decisions.contains("deny") {
            return Err("invariant requires violating example".into());
        }
        Ok(())
        })().map_err(|error| format!("contract={contract_index}: {error}"))?;
    }
    if covered.len() != program.manifest.len() { return Err("missing same-name declaration contract".into()); }
    Ok((projected, corpus))
}

#[tracing::instrument(skip_all, fields(stage = "Read"))]
fn read_source(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|_| "cannot inspect explicit input")?;
    if !meta.file_type().is_file() || meta.len() > MAX_BYTES as u64 {
        return Err("input must be regular bounded file".into());
    }
    let bytes = fs::read(path).map_err(|_| "cannot read explicit input")?;
    if bytes.len() > MAX_BYTES { return Err("source byte budget".into()); }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn encoded(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| "JSON encoding failed")?;
    bytes.push(b'\n');
    if bytes.len() > MAX_BYTES { return Err("generated asset exceeds one MiB".into()); }
    Ok(bytes)
}

struct Arguments {
    source: PathBuf,
    contracts: PathBuf,
    directory: PathBuf,
    check: bool,
}

fn arguments() -> Result<Arguments> {
    let mut args = std::env::args_os().skip(1);
    let mut pairs = BTreeMap::new();
    while let Some(key) = args.next() {
        let key = key.into_string().map_err(|_| "invalid argument encoding")?;
        if !["--source", "--contracts", "--emit-dir", "--check-dir"].contains(&key.as_str()) {
            return Err("unknown argument".into());
        }
        let value = args.next().ok_or("missing argument value")?;
        if pairs.insert(key, PathBuf::from(value)).is_some() { return Err("duplicate argument".into()); }
    }
    if pairs.len() != 3 || pairs.contains_key("--emit-dir") == pairs.contains_key("--check-dir") {
        return Err("require --source PATH --contracts PATH and exactly one output mode".into());
    }
    let check = pairs.contains_key("--check-dir");
    Ok(Arguments {
        source: pairs.remove("--source").ok_or("source required")?,
        contracts: pairs.remove("--contracts").ok_or("contracts required")?,
        directory: pairs.remove(if check { "--check-dir" } else { "--emit-dir" }).ok_or("output required")?,
        check,
    })
}

#[tracing::instrument(skip_all, fields(stage = "Derive"))]
fn derive(args: &Arguments) -> Result<bool> {
    let source = read_source(&args.source)?;
    let contracts = read_source(&args.contracts)?;
    let source_text = std::str::from_utf8(&source).map_err(|_| "source is not UTF-8")?;
    let contract_text = std::str::from_utf8(&contracts).map_err(|_| "contracts are not UTF-8")?;
    // No recursive canonical parse or AST drop may see unchecked hostile depth.
    parse_budget::admit(source_text, false)?;
    parse_budget::admit(contract_text, true)?;
    let program = project(px_compiler::parse(source_text).map_err(|_| "canonical source parse failed")?)?;
    let contract_ast = px_compiler::parse(contract_text).map_err(|_| "canonical contract parse failed")?;
    let (examples, corpus) = oracle(&program, contract_ast)
        .map_err(|error| format!("contract-oracle: {error}"))?;
    let manifest = program.manifest.iter().map(|(name, paths)| {
        Ok(json!({"source_id":name,"id":logical(name)?,"required_paths":paths}))
    }).collect::<Result<Vec<_>>>()?;
    let mut bundle = json!({
        "schema":"1.0","profile":PROFILE,"numeric_profile":NUMERIC_PROFILE,
        "canonical_revision":REVISION,"reducer_version":"1",
        "source_digests":{"source":digest(&source),"contracts":digest(&contracts)},
        "max_safe_int":MAX_INT,"manifest":manifest,
        "rules":program.projected.iter().filter(|v| v["kind"] == "rule").collect::<Vec<_>>(),
        "constraints":program.projected.iter().filter(|v| v["kind"] == "constraint").collect::<Vec<_>>(),
        "contracts":examples
    });
    let content_digest = digest(&encoded(&bundle)?);
    bundle["content_digest"] = json!(content_digest);
    let corpus = json!({
        "schema":"1.0","profile":PROFILE,"numeric_profile":NUMERIC_PROFILE,
        "canonical_revision":REVISION,"bundle_content_digest":content_digest,"cases":corpus
    });
    let assets = [("bundle.json", encoded(&bundle)?), ("canonical-corpus.json", encoded(&corpus)?)];
    if args.check {
        for (name, bytes) in assets {
            if read_source(&args.directory.join(name))? != bytes { return Ok(false); }
        }
    } else {
        let meta = fs::symlink_metadata(&args.directory).map_err(|_| "explicit output directory must exist")?;
        if !meta.file_type().is_dir() { return Err("output is not a real directory".into()); }
        for (name, bytes) in assets {
            let _span = tracing::info_span!("asset_write", stage = "Write").entered();
            let destination = args.directory.join(name);
            let mut file = fs::OpenOptions::new().create_new(true).write(true)
                .open(destination).map_err(|_| "refuse existing output or unsafe destination")?;
            file.write_all(&bytes).map_err(|_| "asset write failed")?;
            file.sync_all().map_err(|_| "asset sync failed")?;
        }
    }
    Ok(true)
}

fn main() {
    tracing_subscriber::fmt().json().with_writer(io::stderr).init();
    let result = arguments().and_then(|args| derive(&args));
    let code = match result {
        Ok(true) => {
            tracing::info!(stage = "Derive", outcome = "Fired", "canonical assets processed");
            0
        }
        Ok(false) => {
            tracing::error!(stage = "Check", outcome = "Rejected", reason = "byte-drift", "canonical asset drift");
            3
        }
        Err(error) => {
            // Adapter errors contain closed schema codes and ordinals, never input values.
            tracing::error!(stage = "Derive", outcome = "Failure", reason = "schema-or-example", failure_code = %error, "derivation rejected");
            2
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projected(expr: &Expr) -> Result<Value> {
        expression(expr, &mut Budget::default(), 0, &mut BTreeSet::new()).map(|(_, v)| v)
    }

    fn comparison(left: AstValue, op: BinOp, right: AstValue) -> Expr {
        Expr::Binary {
            left: Box::new(Expr::Literal(left)),
            op,
            right: Box::new(Expr::Literal(right)),
        }
    }

    #[test]
    fn signed_int53_all_adjacent_boundaries_use_the_canonical_oracle() {
        let values = [-MAX_INT, -MAX_INT + 1, -1, 0, 1, MAX_INT - 1, MAX_INT];
        for left in values {
            for right in values {
                for operator in ["Eq", "Neq", "Gt", "Lt", "Gte", "Lte"] {
                    let (op, expected) = match operator {
                        "Eq" => (BinOp::Eq, left == right),
                        "Neq" => (BinOp::Neq, left != right),
                        "Gt" => (BinOp::Gt, left > right),
                        "Lt" => (BinOp::Lt, left < right),
                        "Gte" => (BinOp::Gte, left >= right),
                        _ => (BinOp::Lte, left <= right),
                    };
                    let expr = comparison(AstValue::Integer(left), op, AstValue::Integer(right));
                    assert!(projected(&expr).is_ok());
                    assert_eq!(evaluate_expr(&expr, &HashMap::new(), &EmptyRegistry).expect("canonical"),
                        json!(expected));
                }
            }
        }
    }

    #[test]
    fn overflow_and_canonical_integer_collapse_are_out_of_profile() {
        for value in [-MAX_INT - 1, MAX_INT + 1, MAX_INT + 2, i64::MIN, i64::MAX] {
            assert!(scalar(&AstValue::Integer(value)).is_err());
        }
        let expr = comparison(AstValue::Integer(MAX_INT + 1), BinOp::Eq, AstValue::Integer(MAX_INT + 2));
        assert!(projected(&expr).is_err());
        // This is a rejected-profile demonstration, never accepted equivalence.
        assert_eq!(evaluate_expr(&expr, &HashMap::new(), &EmptyRegistry).expect("canonical"),
            json!(true));
    }

    #[test]
    fn float_equality_epsilon_and_signed_zero_are_always_rejected() {
        for (left, right) in [(0.0, 1.0e-16), (1.0, 1.0), (-0.0, 0.0)] {
            for op in [BinOp::Eq, BinOp::Neq] {
                let expr = comparison(AstValue::Float(left), op, AstValue::Float(right));
                assert!(projected(&expr).is_err());
            }
        }
        let epsilon = comparison(AstValue::Float(0.0), BinOp::Eq, AstValue::Float(1.0e-16));
        assert_eq!(evaluate_expr(&epsilon, &HashMap::new(), &EmptyRegistry).expect("canonical"),
            json!(true));
    }

    #[test]
    fn finite_float_ordering_preserves_extremes_subnormals_and_zero() {
        let values = [-f64::MAX, -f64::from_bits(1), -0.0, 0.0, f64::from_bits(1), f64::MAX];
        for left in values {
            for right in values {
                for operator in ["Gt", "Lt", "Gte", "Lte"] {
                    let (op, expected) = match operator {
                        "Gt" => (BinOp::Gt, left > right),
                        "Lt" => (BinOp::Lt, left < right),
                        "Gte" => (BinOp::Gte, left >= right),
                        _ => (BinOp::Lte, left <= right),
                    };
                    let expr = comparison(AstValue::Float(left), op, AstValue::Float(right));
                    assert!(projected(&expr).is_ok());
                    assert_eq!(evaluate_expr(&expr, &HashMap::new(), &EmptyRegistry).expect("canonical"),
                        json!(expected));
                }
            }
        }
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(scalar(&AstValue::Float(value)).is_err());
        }
    }

    #[test]
    fn mixed_types_null_and_unreachable_bad_branches_reject() {
        for expr in [
            comparison(AstValue::Boolean(true), BinOp::Eq, AstValue::Integer(1)),
            comparison(AstValue::Integer(1), BinOp::Eq, AstValue::Float(1.0)),
            comparison(AstValue::String("1".into()), BinOp::Eq, AstValue::Integer(1)),
            comparison(AstValue::Null, BinOp::Eq, AstValue::Integer(1)),
        ] {
            assert!(projected(&expr).is_err());
        }
        let expr = Expr::Binary {
            left: Box::new(Expr::Literal(AstValue::Boolean(false))),
            op: BinOp::And,
            right: Box::new(comparison(AstValue::Float(0.0), BinOp::Eq, AstValue::Float(0.0))),
        };
        assert!(projected(&expr).is_err());
    }

    #[test]
    fn pinned_parser_boolean_paths_normalize_before_fact_lookup() {
        for (source, expected) in [("true", true), ("false", false), ("(true)", true)] {
            let expr = px_eval::parse_expr(source).expect("canonical parser");
            let value = projected(&expr).expect("closed normalization");
            let value = if source.starts_with('(') { &value["operand"] } else { &value };
            assert_eq!(value, &literal(Type::Bool, json!(expected)));
        }
        for source in ["null", "True", "FALSE", "nullish", "true_value", "facts.true", "facts.false"] {
            let expr = px_eval::parse_expr(source).expect("canonical path parser");
            assert!(projected(&expr).is_err());
        }
        assert_eq!(projected(&px_eval::parse_expr("\"true\"").expect("quoted string")).expect("literal"),
            literal(Type::String, json!("true")));
    }

    fn example_data(source_value: &str, leaf: &str) -> Result<Value> {
        let source = format!(
            "contract datum:\n  given: \"fixture\"\n  when: \"decode\"\n  then: \"data only\"\n  examples:\n    - input: {{state: {{phase: \"Planned\"}}, event: {{kind: \"OperationRequested\"}}, facts: {{}}}}\n      expect: {{{leaf}: {source_value}}}\n"
        );
        let ast = px_compiler::parse(&source).map_err(|_| "canonical contract parse")?;
        let contract = match &ast.statements[0] {
            Statement::Contract(contract) => contract,
            _ => return Err("wrong declaration".into()),
        };
        contract_data(&contract.examples[0].expect, &mut vec!["expect".into()], &mut Budget::default())
    }

    #[test]
    fn contract_parse_boundary_accepts_complete_authored_document() {
        let source = include_str!("../../../netops/ansible/policy/ansible_molecule.contracts.px");
        let ast = px_compiler::parse(source)
            .unwrap_or_else(|_| panic!("complete authored contract document must parse"));
        let mut examples = 0;
        for statement in ast.statements {
            let contract = match statement {
                Statement::Contract(contract) => contract,
                _ => panic!("authored contract document contains a non-contract declaration"),
            };
            assert!(!contract.examples.is_empty());
            examples += contract.examples.len();
        }
        // Original 215 plus the current, already-authored 25 additive examples.
        // This exact count is a retention assertion, not a lower bound or skip.
        assert_eq!(examples, 240, "retain every original and additive contract example");
    }

    #[test]
    fn contract_parse_boundary_comments_preserve_data_only_at_document_boundaries() {
        let source = "contract datum:\n  examples:\n    - input: {value: -1}\n      expect: {error: null}\n    - input: {value: -0.0}\n      expect: {error: null}\n";
        let baseline = px_compiler::parse(source)
            .unwrap_or_else(|_| panic!("baseline contract fixture must parse"));
        for invalid in [
            source.replace("  examples:\n", "  examples:\n    # fixture note\n"),
            source.replace("    - input: {value: -0.0}", "    # fixture note\n    - input: {value: -0.0}"),
        ] {
            assert!(matches!(px_compiler::parse(&invalid), Err(px_compiler::CompileError::Parse(_))),
                "pinned grammar must reject an interior comment's unconsumed newline");
        }
        let relocated = format!("# fixture note\n{source}\n# second fixture note\n{source}");
        let ast = px_compiler::parse(&relocated)
            .unwrap_or_else(|_| panic!("document-boundary comments must parse"));
        assert_eq!(ast.statements.len(), 2);
        let expected = serde_json::to_value(&baseline.statements[0])
            .unwrap_or_else(|_| panic!("baseline AST must serialize"));
        for statement in ast.statements {
            let actual = serde_json::to_value(statement)
                .unwrap_or_else(|_| panic!("relocated AST must serialize"));
            assert!(actual == expected, "relocating comments must preserve complete contract data");
        }
    }

    #[test]
    fn only_exact_nullable_contract_paths_accept_null() {
        assert_eq!(example_data("null", "error").expect("nullable path"), json!({"error":null}));
        assert!(example_data("null", "decision").is_err());
        for source in ["(null)", "true_value", "True", "FALSE", "facts.null"] {
            assert!(example_data(source, "error").is_err());
        }
        assert_eq!(example_data("\"null\"", "error").expect("quoted string"),
            json!({"error":"null"}));
        assert_eq!(example_data("true", "error").expect("canonical value boolean"),
            json!({"error":true}));
        // Data decoding preserves types; the later nullable field schema rejects this bool.
        for keyword in ["true", "false"] {
            let expr = px_eval::parse_expr(keyword).expect("canonical keyword path");
            let path = match expr {
                Expr::Path(path) => path,
                _ => panic!("pinned expression keyword path changed"),
            };
            assert!(contract_data(&AstValue::Path(path), &mut vec!["expect".into(), "error".into()],
                &mut Budget::default()).is_err());
        }
        let expr = px_eval::parse_expr("null").expect("canonical null expression path");
        let ident = match expr {
            Expr::Path(path) => path.segments.into_iter().next().expect("single segment"),
            _ => panic!("pinned expression null shape changed"),
        };
        assert!(contract_data(&AstValue::Ident(ident), &mut vec!["expect".into(), "error".into()],
            &mut Budget::default()).is_err());
    }

    #[test]
    fn duplicate_contract_keys_and_parameters_are_not_overwritten() {
        assert!(example_data("\"a\", error: \"b\"", "error").is_err());
        let source = "rule netops_companion_catalog_operation_requested_set_phase:\n  when:\n    - event.kind == \"OperationRequested\"\n  then:\n    - action: set_phase phase: \"Planned\" phase: \"Active\"\n";
        assert!(project(px_compiler::parse(source).expect("canonical parse")).is_err());
    }

    #[test]
    fn rejection_diagnostics_identify_source_declaration_without_authored_values() {
        let source = "rule netops_companion_catalog_operation_requested_set_phase:\n  when:\n    - event.kind == \"OperationRequested\"\n  then:\n    - action: request_effect kind: \"private-authored-value\"\n";
        let error = project(px_compiler::parse(source).expect("canonical parse"))
            .err().expect("invalid constant must reject");
        assert_eq!(error, "source-project declaration=0: unknown static action or constant parameter");
        assert!(!error.contains("private-authored-value"));
    }

    #[test]
    fn rejection_diagnostics_identify_contract_and_example_without_authored_values() {
        let source = "rule netops_companion_catalog_operation_requested_set_phase:\n  when:\n    - event.kind == \"OperationRequested\"\n  then:\n    - action: set_phase phase: \"Planned\"\n";
        let contracts = "contract netops_companion_catalog_operation_requested_set_phase_contract:\n  examples:\n    - input: {state: {phase: \"Planned\"}, event: {kind: \"OperationRequested\"}, facts: {}}\n      expect: {decision: \"private-authored-value\", reason: null, actions: [], next_phase: null, aggregate: null, constraint_outcomes: {}, error: null}\n";
        let program = project(px_compiler::parse(source).expect("canonical source")).expect("projection");
        let error = oracle(&program, px_compiler::parse(contracts).expect("canonical contracts"))
            .expect_err("invalid decision must reject");
        assert_eq!(error, "contract=0: example=0: unknown expected decision");
        assert!(!error.contains("private-authored-value"));
    }

    #[test]
    fn revision_counter_types_and_resource_budgets_are_closed() {
        let path = vec!["state".into(), "revision".into()];
        for value in [json!(-1), json!(MAX_INT + 1), json!(1.0), json!(true), Value::Null] {
            assert!(validate_leaf(&path, &value).is_err());
        }
        assert!(validate_leaf(&path, &json!(MAX_INT)).is_ok());
        let mut budget = Budget::default();
        assert!(budget.enter(MAX_DEPTH + 1).is_err());
        assert!(budget.visit(MAX_VISITS + 1).is_err());
        assert!(text(&"x".repeat(MAX_STRING + 1)).is_err());
        assert!(logical("netops_companion_unknown_operation_requested_success").is_err());
        assert!(action("request_effect", &[("kind".into(), json!("arbitrary-executable"))]).is_err());
    }
}

#[cfg(test)]
mod nov11_independent {
    use super::*;

    fn negate(operand: Expr) -> Expr {
        Expr::Unary { op: UnaryOp::Neg, operand: Box::new(operand) }
    }

    fn project(expr: &Expr) -> Result<Value> {
        expression(expr, &mut Budget::default(), 0, &mut BTreeSet::new()).map(|(_, v)| v)
    }

    #[test]
    fn signed_int_boundaries() {
        let boundaries = [-MAX_INT, -MAX_INT + 1, -1, 0, 1, MAX_INT - 1, MAX_INT];
        for value in boundaries {
            let direct = Expr::Literal(AstValue::Integer(value));
            let unary = negate(direct.clone());
            assert_eq!(project(&direct).expect("direct literal"), literal(Type::Int, json!(value)));
            assert_eq!(project(&unary).expect("constant unary"), literal(Type::Int, json!(-value)));
            for other in boundaries {
                for (op, expected) in [
                    (BinOp::Eq, -value == other), (BinOp::Neq, -value != other),
                    (BinOp::Gt, -value > other), (BinOp::Lt, -value < other),
                    (BinOp::Gte, -value >= other), (BinOp::Lte, -value <= other),
                ] {
                    let expr = Expr::Binary {
                        left: Box::new(unary.clone()), op,
                        right: Box::new(Expr::Literal(AstValue::Integer(other))),
                    };
                    assert!(project(&expr).is_ok());
                    assert_eq!(
                        evaluate_expr(&expr, &HashMap::new(), &EmptyRegistry).expect("canonical"),
                        json!(expected),
                    );
                }
            }
        }
        for value in [-MAX_INT - 1, MAX_INT + 1, i64::MIN, i64::MAX] {
            assert_eq!(project(&Expr::Literal(AstValue::Integer(value))).unwrap_err(),
                       "unsupported scalar or numeric domain");
            assert_eq!(project(&negate(Expr::Literal(AstValue::Integer(value)))).unwrap_err(),
                       "negation requires an in-profile numeric literal constant");
        }
    }

    #[test]
    fn signed_float_boundaries_and_negative_zero() {
        let boundaries = [
            -f64::MAX, -f64::from_bits(1), -0.0, 0.0, f64::from_bits(1), f64::MAX,
        ];
        for value in boundaries {
            let direct = project(&Expr::Literal(AstValue::Float(value))).expect("finite literal");
            assert_eq!(direct["type"], "float");
            assert_eq!(direct["value"].as_f64().expect("binary64").to_bits(), value.to_bits());
            let unary = negate(Expr::Literal(AstValue::Float(value)));
            let projected = project(&unary).expect("finite unary literal");
            assert_eq!(projected["type"], "float");
            assert_eq!(projected["value"].as_f64().expect("binary64").to_bits(), (-value).to_bits());
            for other in boundaries {
                for (op, expected) in [
                    (BinOp::Gt, -value > other), (BinOp::Lt, -value < other),
                    (BinOp::Gte, -value >= other), (BinOp::Lte, -value <= other),
                ] {
                    let expr = Expr::Binary {
                        left: Box::new(unary.clone()), op,
                        right: Box::new(Expr::Literal(AstValue::Float(other))),
                    };
                    assert!(project(&expr).is_ok());
                    assert_eq!(
                        evaluate_expr(&expr, &HashMap::new(), &EmptyRegistry).expect("canonical"),
                        json!(expected),
                    );
                }
            }
        }
        let negative_zero = project(&negate(Expr::Literal(AstValue::Float(0.0)))).expect("zero");
        assert!(serde_json::to_string(&negative_zero).expect("JSON").contains("-0.0"));
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(project(&Expr::Literal(AstValue::Float(value))).unwrap_err(),
                       "unsupported scalar or numeric domain");
            assert_eq!(project(&negate(Expr::Literal(AstValue::Float(value)))).unwrap_err(),
                       "negation requires an in-profile numeric literal constant");
        }
    }

    #[test]
    fn dynamic_nested_paren_and_arithmetic_negation_reject() {
        let one = Expr::Literal(AstValue::Integer(1));
        let path = Expr::Path(px_ast::DottedIdent::from_parts(vec!["health", "reading"]));
        let call = Expr::Call { name: px_ast::Ident::new("lookup"), args: vec![] };
        let var = Expr::Var(px_ast::VarRef {
            name: px_ast::Ident::new("value"), accessors: vec![], span: None,
        });
        for operand in [
            path, call, var, negate(one.clone()), Expr::Paren(Box::new(one.clone())),
            Expr::Binary {
                left: Box::new(one.clone()), op: BinOp::Add, right: Box::new(one.clone()),
            },
            Expr::Literal(AstValue::Boolean(true)), Expr::Literal(AstValue::String("1".into())),
            Expr::Literal(AstValue::Null),
        ] {
            let invalid = negate(operand);
            assert_eq!(project(&invalid).unwrap_err(),
                       "negation requires an in-profile numeric literal constant");
            for (op, left) in [(BinOp::Or, true), (BinOp::And, false)] {
                let dead = Expr::Binary {
                    left: Box::new(Expr::Literal(AstValue::Boolean(left))), op,
                    right: Box::new(invalid.clone()),
                };
                assert_eq!(project(&dead).unwrap_err(),
                           "negation requires an in-profile numeric literal constant");
            }
        }
        let outer = project(&Expr::Paren(Box::new(negate(one)))).expect("outer parentheses");
        assert_eq!(outer, json!({
            "kind": "paren", "operand": {"kind": "literal", "type": "int", "value": -1},
        }));
    }

    #[test]
    fn unary_budget_counts_both_nodes() {
        let unary = negate(Expr::Literal(AstValue::Integer(1)));
        let mut budget = Budget { nodes: MAX_NODES - 2, visits: 0 };
        assert!(expression(&unary, &mut budget, 0, &mut BTreeSet::new()).is_ok());
        assert_eq!(budget.nodes, MAX_NODES);
        let mut exhausted = Budget { nodes: MAX_NODES - 1, visits: 0 };
        assert_eq!(expression(&unary, &mut exhausted, 0, &mut BTreeSet::new()).unwrap_err(),
                   "policy AST budget exceeded");
        assert_eq!(exhausted.nodes, MAX_NODES + 1);
        assert!(expression(&unary, &mut Budget::default(), MAX_DEPTH - 1,
                           &mut BTreeSet::new()).is_ok());
        assert_eq!(expression(&unary, &mut Budget::default(), MAX_DEPTH,
                              &mut BTreeSet::new()).unwrap_err(),
                   "policy AST budget exceeded");
    }

    #[test]
    fn unary_mixed_types_and_float_equality_reject() {
        for op in [BinOp::Eq, BinOp::Neq] {
            let expr = Expr::Binary {
                left: Box::new(negate(Expr::Literal(AstValue::Float(0.0)))), op,
                right: Box::new(Expr::Literal(AstValue::Float(0.0))),
            };
            assert_eq!(project(&expr).unwrap_err(), "operator/type pair outside numeric profile");
        }
        for (left, right) in [
            (negate(Expr::Literal(AstValue::Integer(1))), Expr::Literal(AstValue::Float(0.0))),
            (negate(Expr::Literal(AstValue::Float(1.0))), Expr::Literal(AstValue::Integer(0))),
        ] {
            let expr = Expr::Binary { left: Box::new(left), op: BinOp::Lt, right: Box::new(right) };
            assert_eq!(project(&expr).unwrap_err(), "mixed comparison domains");
        }
    }

    #[test]
    fn closed_next_occurrence_leaf_and_path() {
        let path = vec!["lifecycle".into(), "next_effect_kind".into()];
        assert_eq!(field_type(&path).expect("closed path"), Type::String);
        for kind in [
            "dependency-probe", "dependency-download", "dependency-stage", "dependency-verify",
            "dependency-activate", "dependency-uninstall", "restore-active-pointer", "none",
        ] {
            assert_eq!(validate_leaf(&path, &json!(kind)), Ok(()));
        }
        for value in [
            Value::Null, json!(true), json!(false), json!(0), json!(1.0), json!([]), json!({}),
        ] {
            assert_eq!(validate_leaf(&path, &value).unwrap_err(), "fact type/domain mismatch");
        }
        for value in ["NONE", "none ", "apply", "dependency-probe ", "", "none\0"] {
            assert_eq!(validate_leaf(&path, &json!(value)).unwrap_err(),
                       "fact enum outside closed schema");
        }
        for path in [
            vec!["lifecycle".into(), "ordinal".into()],
            vec!["lifecycle".into(), "next_effect_kind".into(), "value".into()],
        ] {
            assert_eq!(field_type(&path).unwrap_err(), "path is not an exact typed feature fact");
            assert_eq!(validate_leaf(&path, &json!("none")).unwrap_err(),
                       "path is not an exact typed feature fact");
        }
    }
}
