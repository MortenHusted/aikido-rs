//! `--jq` filtering via the jaq crates (the Rust jq implementation).
//!
//! Matches the Go CLI's gojq behaviour: the expression runs over the
//! envelope's `data` value (not the full envelope), and each result is
//! printed as pretty JSON, one after another.

use anyhow::{anyhow, Context};
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{data, unwrap_valr, Ctx, Vars};
use jaq_json::Val;
use serde::Deserialize;
use serde_json::Value;

/// Run `expr` over `data` and print each result to stdout as pretty JSON.
pub fn render(data: &Value, expr: &str) -> anyhow::Result<()> {
    for result in run(data, expr)? {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    Ok(())
}

/// Run `expr` over `data`, collecting all results.
pub fn run(data: &Value, expr: &str) -> anyhow::Result<Vec<Value>> {
    let program = File {
        code: expr,
        path: (),
    };
    let loader = Loader::new(
        jaq_core::defs()
            .chain(jaq_std::defs())
            .chain(jaq_json::defs()),
    );
    let arena = Arena::default();
    let modules = loader
        .load(&arena, program)
        .map_err(|errs| anyhow!("invalid jq expression: {}", load_error_text(&errs)))?;
    let filter = jaq_core::Compiler::default()
        .with_funs(
            jaq_core::funs()
                .chain(jaq_std::funs())
                .chain(jaq_json::funs()),
        )
        .compile(modules)
        .map_err(|errs| anyhow!("invalid jq expression: {}", compile_error_text(&errs)))?;

    let input = Val::deserialize(data.clone()).context("converting data for jq")?;
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));

    let mut results = Vec::new();
    for output in filter.id.run((ctx, input)).map(unwrap_valr) {
        let val = output.map_err(|err| anyhow!("jq evaluation error: {err}"))?;
        // Val's Display renders valid JSON; round-trip into serde_json for
        // uniform pretty-printing.
        let json: Value = serde_json::from_str(&val.to_string())
            .with_context(|| format!("jq produced non-JSON output: {val}"))?;
        results.push(json);
    }
    Ok(results)
}

fn load_error_text<E: std::fmt::Debug>(errs: &E) -> String {
    format!("{errs:?}")
}

fn compile_error_text<E: std::fmt::Debug>(errs: &E) -> String {
    format!("{errs:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_returns_input() {
        let data = json!({"a": 1});
        assert_eq!(run(&data, ".").unwrap(), vec![data]);
    }

    #[test]
    fn iterates_and_projects_fields() {
        let data = json!([{"severity": "high", "id": 1}, {"severity": "low", "id": 2}]);
        let results = run(&data, ".[] | .severity").unwrap();
        assert_eq!(results, vec![json!("high"), json!("low")]);
    }

    #[test]
    fn supports_std_functions() {
        let data = json!([3, 1, 2]);
        assert_eq!(run(&data, "sort").unwrap(), vec![json!([1, 2, 3])]);
        assert_eq!(run(&data, "length").unwrap(), vec![json!(3)]);
    }

    #[test]
    fn select_filters_rows() {
        let data = json!([{"s": "high"}, {"s": "low"}]);
        let results = run(&data, r#"[.[] | select(.s == "high")] | length"#).unwrap();
        assert_eq!(results, vec![json!(1)]);
    }

    #[test]
    fn invalid_expression_is_a_clear_error() {
        let err = run(&json!(null), ".[").unwrap_err();
        assert!(err.to_string().contains("invalid jq expression"));
    }
}
