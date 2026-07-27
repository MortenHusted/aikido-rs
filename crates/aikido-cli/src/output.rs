//! Output formats and the JSON envelope contract.
//!
//! The envelope is a hard interface consumed by scheduled automation:
//!
//! ```json
//! {"ok": true, "data": <any>, "summary": "...", "meta": {...}}
//! {"ok": false, "error": "...", "code": "...", "hint": "..."}
//! ```
//!
//! `data`, `summary`, `meta`, and `hint` are omitted when empty. Success
//! envelopes go to stdout; error envelopes go to stderr with a non-zero exit
//! (the Go CLI printed some errors to stdout with exit 0 — that was a bug,
//! not a contract).

use std::io::IsTerminal;

use serde::Serialize;
use serde_json::Value;

use aikido_core::error::ApiError;

/// Successful response envelope. Field order matters: it is part of the
/// byte-level output contract.
#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

impl Response {
    pub fn new(data: Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            summary: String::new(),
            meta: None,
        }
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    pub fn with_count(mut self, count: usize) -> Self {
        self.meta = Some(serde_json::json!({ "count": count }));
        self
    }

    /// Envelope with no data — used by mutation commands.
    pub fn summary_only(summary: impl Into<String>) -> Self {
        Self {
            ok: true,
            data: None,
            summary: summary.into(),
            meta: None,
        }
    }
}

/// Error envelope, matching the Go shape byte for byte.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub ok: bool,
    pub error: String,
    pub code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hint: String,
}

impl From<&ApiError> for ErrorEnvelope {
    fn from(err: &ApiError) -> Self {
        Self {
            ok: false,
            error: err.to_string(),
            code: err.code().to_string(),
            hint: err.hint().unwrap_or_default().to_string(),
        }
    }
}

/// Resolved output format. Precedence: `--jq` > `--quiet` > `--json` >
/// `--md` > auto (TTY → styled, pipe → JSON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    Json,
    /// JSON filtered through a jq expression (data only, not the envelope).
    Jq(String),
    Markdown,
    Quiet,
    Styled,
}

#[derive(Debug, Clone, Default)]
pub struct GlobalFlags {
    pub json: bool,
    pub jq: Option<String>,
    pub md: bool,
    pub quiet: bool,
    pub verbose: bool,
}

impl GlobalFlags {
    pub fn format(&self) -> Format {
        if let Some(expr) = self.jq.as_ref().filter(|e| !e.is_empty()) {
            return Format::Jq(expr.clone());
        }
        if self.quiet {
            return Format::Quiet;
        }
        if self.json {
            return Format::Json;
        }
        if self.md {
            return Format::Markdown;
        }
        if std::io::stdout().is_terminal() {
            Format::Styled
        } else {
            Format::Json
        }
    }
}

/// A column in markdown table output.
pub struct Column {
    pub header: &'static str,
    pub key: &'static str,
}

/// Render a successful response to stdout in the requested format.
pub fn render_ok(
    format: &Format,
    resp: Response,
    columns: &[Column],
    formatter: Option<&dyn Fn(&Value) -> String>,
) -> anyhow::Result<()> {
    match format {
        Format::Json => print_pretty(&resp),
        Format::Jq(expr) => crate::jq::render(resp.data.as_ref().unwrap_or(&Value::Null), expr),
        Format::Quiet => print_pretty(&resp.data),
        Format::Markdown => {
            render_markdown(&resp, columns);
            Ok(())
        }
        Format::Styled => {
            render_styled(&resp, formatter);
            Ok(())
        }
    }
}

/// Render an error envelope to stderr. Styled mode gets a human-readable
/// message; every other mode gets the JSON envelope.
pub fn render_err(format: &Format, err: &ApiError) {
    let envelope = ErrorEnvelope::from(err);
    if *format == Format::Styled {
        eprintln!("Error: {}", envelope.error);
        eprintln!("({})", envelope.code);
        if !envelope.hint.is_empty() {
            eprintln!("Hint: {}", envelope.hint);
        }
    } else {
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&envelope)
                .unwrap_or_else(|_| format!("{{\"ok\":false,\"error\":\"{}\"}}", envelope.error))
        );
    }
}

fn print_pretty<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn render_markdown(resp: &Response, columns: &[Column]) {
    if columns.is_empty() {
        // No table shape defined — fall back to JSON so output is never
        // silently empty.
        let _ = print_pretty(resp);
        return;
    }

    let rows: Vec<&serde_json::Map<String, Value>> = resp
        .data
        .as_ref()
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default();

    let headers: Vec<&str> = columns.iter().map(|c| c.header).collect();
    println!("| {} |", headers.join(" | "));
    println!("| {} |", vec!["---"; columns.len()].join(" | "));
    for row in rows {
        let cells: Vec<String> = columns
            .iter()
            .map(|col| row.get(col.key).map(cell_text).unwrap_or_default())
            .collect();
        println!("| {} |", cells.join(" | "));
    }
    if !resp.summary.is_empty() {
        println!("\n{}", resp.summary);
    }
}

fn render_styled(resp: &Response, formatter: Option<&dyn Fn(&Value) -> String>) {
    if let Some(data) = &resp.data {
        let items: Vec<&Value> = match data {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        for item in items {
            match formatter {
                Some(f) => println!("{}", f(item)),
                None => println!(
                    "{}",
                    serde_json::to_string_pretty(item).unwrap_or_else(|_| item.to_string())
                ),
            }
        }
    }
    if !resp.summary.is_empty() {
        // Faint summary line, like the Go CLI.
        println!("\x1b[2m{}\x1b[0m", resp.summary);
    }
}

/// Extract a display string from a JSON value (objects/arrays fall back to
/// compact JSON).
pub fn cell_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// String field from a JSON object, empty when missing.
pub fn str_val(item: &Value, key: &str) -> String {
    item.get(key).map(cell_text).unwrap_or_default()
}

/// ANSI severity badge for TTY output.
pub fn severity_badge(severity: &str) -> String {
    let (bg, fg, label) = match severity.to_lowercase().as_str() {
        "critical" => ("41", "97", " CRIT "),
        "high" => ("48;5;166", "97", " HIGH "),
        "medium" => ("48;5;178", "30", " MED  "),
        "low" => ("44", "97", " LOW  "),
        other => return format!(" {} ", other.to_uppercase()),
    };
    format!("\x1b[{bg};{fg};1m{label}\x1b[0m")
}

/// Ordered key/value lines for a detail view.
pub fn detail_lines(pairs: &[(&str, String)]) -> String {
    let lines: Vec<String> = pairs
        .iter()
        .map(|(label, value)| format!("{:<14} {}", format!("{label}:"), value))
        .collect();
    lines.join("\n")
}
