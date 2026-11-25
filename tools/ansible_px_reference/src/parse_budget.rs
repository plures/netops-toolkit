//! Budget-only admission before the pinned recursive parser constructs an AST.
//! This does not parse, repair or normalize PX. Canonical parsing and projection
//! remain authoritative for grammar, node counts, types and all output bytes.

use crate::{Result, MAX_BYTES, MAX_DEPTH, MAX_NODES};

const REJECTED: &str = "policy AST budget exceeded before canonical parse";

fn quoted(bytes: &[u8], index: &mut usize) -> Result<()> {
    let quote = bytes[*index];
    *index += 1;
    while *index < bytes.len() {
        match bytes[*index] {
            b'\\' => {
                // Pinned string grammar: backslash followed by ANY, not JSON escapes.
                *index += 1;
                if *index == bytes.len() {
                    return Err("canonical input has an unfinished quoted token".into());
                }
                *index += 1;
            }
            byte if byte == quote => {
                *index += 1;
                return Ok(());
            }
            _ => *index += 1,
        }
    }
    Err("canonical input has an unfinished quoted token".into())
}

fn comment(bytes: &[u8], index: usize) -> bool {
    bytes[index] == b'#' || bytes[index..].starts_with(b"//")
}

fn budget_text(source: &str) -> Result<String> {
    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\'' || bytes[index] == b'"' {
            let start = index;
            quoted(bytes, &mut index)?;
            // A string is a single leaf even if its grammar permits newlines.
            // This mask is used ONLY to measure heights, never passed to parse.
            masked[start..index].fill(b' ');
            masked[start] = b'0';
        } else if comment(bytes, index) {
            let start = index;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            masked[start..index].fill(b' ');
        } else {
            index += 1;
        }
    }
    String::from_utf8(masked).map_err(|_| "canonical input is not UTF-8".into())
}

fn delimiters(source: &str) -> Result<()> {
    let bytes = source.as_bytes();
    let mut stack = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => quoted(bytes, &mut index)?,
            _ if comment(bytes, index) => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'(' | b'[' | b'{' => {
                if stack.len() == MAX_DEPTH {
                    return Err(REJECTED.into());
                }
                stack.push(bytes[index]);
                index += 1;
            }
            b')' | b']' | b'}' => {
                let opener = match bytes[index] {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                if stack.pop() != Some(opener) {
                    return Err("canonical input has unmatched delimiters".into());
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    if !stack.is_empty() {
        return Err("canonical input has unmatched delimiters".into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Operator {
    Open,
    Unary,
    Binary(u8),
}

impl Operator {
    fn precedence(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Unary => 6,
            Self::Binary(priority) => priority,
        }
    }
}

fn bounded(depth: usize) -> Result<usize> {
    if depth > MAX_DEPTH {
        Err(REJECTED.into())
    } else {
        Ok(depth)
    }
}

fn reduce(operator: Operator, operands: &mut Vec<usize>) -> Result<()> {
    let right = operands
        .pop()
        .ok_or("canonical expression lacks an operand")?;
    let depth = match operator {
        Operator::Unary => right + 1,
        Operator::Binary(_) => {
            let left = operands
                .pop()
                .ok_or("canonical expression lacks an operand")?;
            left.max(right) + 1
        }
        Operator::Open => return Err("canonical expression has unmatched parentheses".into()),
    };
    operands.push(bounded(depth)?);
    Ok(())
}

/// Heights only, no recursive nodes. Pinned V1 logic operators share one
/// precedence and fold LEFT (including mixed and/or); power folds RIGHT.
/// A parenthesis and a unary sign each contribute one original AST node.
fn expression_height(source: &str) -> Result<()> {
    let bytes = source.as_bytes();
    let mut operands = Vec::new();
    let mut operators = Vec::new();
    let mut index = 0;
    let mut needs_operand = true;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if comment(bytes, index) {
            break;
        }
        if needs_operand {
            if bytes[index] == b'(' {
                operators.push(Operator::Open);
                index += 1;
                continue;
            }
            if bytes[index] == b'-'
                || bytes[index] == b'!'
                || bytes[index..].starts_with(b"not")
                || bytes[index..].starts_with(b"NOT")
            {
                operators.push(Operator::Unary);
                index += if bytes[index] == b'-' || bytes[index] == b'!' {
                    1
                } else {
                    3
                };
                // A prefix chain without parentheses is out of the closed grammar,
                // but still must not grow our own stack with adversarial input.
                if operators.len() > MAX_NODES {
                    return Err(REJECTED.into());
                }
                continue;
            }
            if bytes[index] == b'"' || bytes[index] == b'\'' {
                quoted(bytes, &mut index)?;
            } else {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric()
                        || bytes[index] == b'_'
                        || bytes[index] == b'.')
                {
                    index += 1;
                }
                if start == index {
                    return Err("expression construct outside closed profile".into());
                }
            }
            operands.push(0);
            needs_operand = false;
            continue;
        }
        if bytes[index] == b')' {
            while let Some(operator) = operators.pop() {
                if matches!(operator, Operator::Open) {
                    let height = operands
                        .pop()
                        .ok_or("canonical expression lacks an operand")?;
                    operands.push(bounded(height + 1)?);
                    break;
                }
                reduce(operator, &mut operands)?;
            }
            index += 1;
            continue;
        }
        let rest = &bytes[index..];
        let (width, priority) = if rest.starts_with(b"&&") || rest.starts_with(b"||") {
            (2, 1)
        } else if rest.starts_with(b"AND") || rest.starts_with(b"and") {
            (3, 1)
        } else if rest.starts_with(b"OR") || rest.starts_with(b"or") {
            (2, 1)
        } else if [b"==", b"!=", b">=", b"<="]
            .iter()
            .any(|token| rest.starts_with(*token))
        {
            (2, 2)
        } else {
            match bytes[index] {
                b'>' | b'<' => (1, 2),
                b'+' | b'-' => (1, 3),
                b'*' | b'/' | b'%' => (1, 4),
                b'^' => (1, 5),
                _ => return Err("expression construct outside closed profile".into()),
            }
        };
        while let Some(operator) = operators.last().copied() {
            if matches!(operator, Operator::Open)
                || operator.precedence() < priority
                || (priority == 5 && operator.precedence() == priority)
            {
                break;
            }
            operators.pop();
            reduce(operator, &mut operands)?;
        }
        operators.push(Operator::Binary(priority));
        index += width;
        needs_operand = true;
    }
    if needs_operand {
        return Err("canonical expression lacks an operand".into());
    }
    while let Some(operator) = operators.pop() {
        reduce(operator, &mut operands)?;
    }
    if operands.len() != 1 {
        return Err("canonical expression has extra operands".into());
    }
    Ok(())
}

/// Admission only. Reject unsupported declarations before they can invoke
/// recursive parser branches which the subsequent closed projection forbids.
pub(super) fn admit(source: &str, contracts: bool) -> Result<()> {
    if source.len() > MAX_BYTES {
        return Err("source byte budget".into());
    }
    delimiters(source)?;
    let masked = budget_text(source)?;
    // Contract values in the closed profile are scalar/map/list data only.
    // Paths are allowed solely for exact nullable leaves, never calls/Paren.
    if contracts && masked.contains('(') {
        return Err("contract expression outside closed data profile".into());
    }
    let mut conditions = false;
    let mut containers = 0usize;
    for line in masked.lines() {
        let trimmed = line.trim();
        let top_level = containers == 0;
        for byte in line.bytes() {
            match byte {
                b'{' | b'[' => containers += 1,
                b'}' | b']' => containers -= 1,
                _ => {}
            }
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        // The pinned grammar does not enforce indentation or require whitespace
        // between a declaration keyword and its identifier. Do not add either.
        if (contracts && trimmed.starts_with("contract"))
            || (!contracts && (trimmed.starts_with("rule") || trimmed.starts_with("constraint")))
        {
            conditions = false;
            continue;
        }
        if contracts {
            if top_level
                && [
                    "import",
                    "entity",
                    "config",
                    "fact",
                    "rule",
                    "constraint",
                    "function",
                    "trigger",
                    "procedure",
                    "scenario",
                    "type",
                ]
                .iter()
                .any(|prefix| trimmed.starts_with(prefix))
            {
                return Err("source contains unsupported declaration".into());
            }
            continue;
        }
        if trimmed == "when:" {
            conditions = true;
        } else if let Some(expression) = trimmed
            .strip_prefix("when:")
            .or_else(|| trimmed.strip_prefix("require:"))
        {
            expression_height(expression)?;
            conditions = false;
        } else if conditions && trimmed.starts_with('-') {
            expression_height(&trimmed[1..])?;
        } else {
            conditions = false;
            let metadata = [
                "then:",
                "priority:",
                "severity:",
                "message:",
                "scope:",
                "phase:",
                "trait:",
                "weight:",
                "prompt:",
            ]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix));
            let action = trimmed
                .strip_prefix('-')
                .is_some_and(|body| body.trim_start().starts_with("action:"));
            if (!metadata && !action) || trimmed.contains('(') {
                return Err("expression construct outside closed profile".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_boundary_and_unary_are_exact() {
        for depth in 0..=MAX_DEPTH {
            let expression = format!("{}true{}", "(".repeat(depth), ")".repeat(depth));
            assert!(expression_height(&expression).is_ok(), "depth={depth}");
        }
        let expression = format!(
            "{}true{}",
            "(".repeat(MAX_DEPTH + 1),
            ")".repeat(MAX_DEPTH + 1)
        );
        assert!(expression_height(&expression).is_err());
        assert!(expression_height(&format!("{}!true{}", "(".repeat(31), ")".repeat(31))).is_ok());
        assert!(expression_height(&format!("{}!true{}", "(".repeat(32), ")".repeat(32))).is_err());
    }

    #[test]
    fn flat_chains_reject_before_recursive_ast_destruction() {
        for operator in ["and", "or", "AND", "OR", "&&", "||", "+", "*", "^"] {
            let boundary = vec!["true"; MAX_DEPTH + 1].join(&format!(" {operator} "));
            assert!(expression_height(&boundary).is_ok(), "{operator}");
            let overflow = vec!["true"; MAX_DEPTH + 2].join(&format!(" {operator} "));
            assert!(expression_height(&overflow).is_err(), "{operator}");
        }
        let long = vec!["true"; 32_768].join(" and ");
        assert!(expression_height(&long).is_err());
    }

    #[test]
    fn balanced_many_nodes_preserve_height_not_operator_count() {
        let mut expression = "true".to_string();
        for _ in 0..10 {
            expression = format!("({expression}) and ({expression})");
        }
        assert!(expression_height(&expression).is_ok());
    }

    #[test]
    fn lexical_strings_and_both_pinned_comments_are_opaque() {
        for quote in ['\'', '"'] {
            let source = format!("{quote}{} # // \\{quote} ){quote}", "(".repeat(1000));
            assert!(delimiters(&source).is_ok());
            assert!(expression_height(&format!("{source} == {source}")).is_ok());
        }
        assert!(delimiters("# (((((((\n// [[[[[\n'{}'").is_ok());
        assert!(expression_height("true // (((\n").is_ok());
        assert!(expression_height("true # (((\n").is_ok());
    }

    #[test]
    fn both_document_operands_admit_before_canonical_parse() {
        let parentheses = format!("{}true{}", "(".repeat(10_000), ")".repeat(10_000));
        let source =
            format!("rule netops_companion_catalog_probe:\n  when:\n    - {parentheses}\n");
        assert!(admit(&source, false).is_err());
        let maps = format!("{}true{}", "{x:".repeat(10_000), "}".repeat(10_000));
        assert!(admit(
            &format!("contract datum:\n  examples:\n    - input: {maps}\n"),
            true
        )
        .is_err());
        let chain = vec!["true"; 10_000].join(" and ");
        assert!(admit(&format!("constraint datum:\n  when: {chain}\n"), false).is_err());
    }

    #[test]
    fn multiline_strings_never_create_budget_syntax() {
        let source = "rule netops_companion_catalog_probe:\n  when:\n    - request.mode == 'preview\nrule not_a_declaration:\n((((('\n  then:\n    - action: set_phase phase: 'Planned'\n";
        assert!(admit(source, false).is_ok());
        let contracts = "contract datum:\n  given: 'text\n((((( and true'\n";
        assert!(admit(contracts, true).is_ok());
    }

    #[test]
    fn pinned_whitespace_is_not_replaced_with_an_indentation_grammar() {
        let source = "rulenetops_companion_catalog_probe:\nwhen:\n-event.kind == 'OperationRequested'\nthen:\n-action:set_phase phase:'Planned'\n";
        assert!(admit(source, false).is_ok());
        assert!(px_compiler::parse(source).is_ok());
        let contracts =
            "contractdatum:\ngiven:'fixture'\nexamples:\n-input:{value:1}\nexpect:{error:null}\n";
        assert!(admit(contracts, true).is_ok());
        assert!(px_compiler::parse(contracts).is_ok());
        let multiline = "contract datum:\nexamples:\n-input:{\nfacts:{value:1},\nconfig:{enabled:true}\n}\nexpect:{error:null}\n";
        assert!(admit(multiline, true).is_ok());
        assert!(px_compiler::parse(multiline).is_ok());
    }
}
