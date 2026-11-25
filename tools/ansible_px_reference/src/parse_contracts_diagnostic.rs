//! Private build-only diagnostic, not the producer CLI or a policy evaluator.
//! Compile only against the independently bound, already installed pinned rlibs.

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

const STAGE: &str = "ParseContractsDiagnostic";
const MAX_BYTES: u64 = 1_048_576;

fn input() -> Result<String, &'static str> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--contracts")) {
        return Err("require --contracts PATH");
    }
    let path = PathBuf::from(args.next().ok_or("contracts path required")?);
    if args.next().is_some() {
        return Err("unexpected argument");
    }
    let file = File::open(path).map_err(|_| "contracts open failed")?;
    let metadata = file.metadata().map_err(|_| "contracts metadata failed")?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err("contracts must be a bounded regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "contracts read failed")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("contracts byte limit");
    }
    String::from_utf8(bytes).map_err(|_| "contracts are not UTF-8")
}

fn main() {
    tracing_subscriber::fmt().json().with_writer(io::stderr).init();
    let text = match input() {
        Ok(text) => text,
        Err(code) => {
            tracing::error!(stage = STAGE, outcome = "Rejected",
                reason = "diagnostic-input", failure_code = code,
                "parse-only input rejected");
            std::process::exit(2);
        }
    };
    // Do not map, truncate, redact, reparse or infer a span from this error.
    // At the pinned revision Parse(String) already contains pest's original
    // line/column diagnostic; Unsupported/Internal need not contain any span.
    match px_compiler::parse(&text) {
        Err(error) => {
            tracing::error!(stage = STAGE, outcome = "Failure",
                reason = "original-compile-error", compile_error = ?error,
                diagnostic = %error, "pinned contract parse failed");
            std::process::exit(2);
        }
        Ok(_) => {
            tracing::info!(stage = STAGE, outcome = "UnexpectedSuccess",
                "pinned contract parse succeeded; stop without derivation");
        }
    }
}
