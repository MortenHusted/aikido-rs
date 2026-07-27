//! `aikido containers` — list, show, export licenses.

use aikido_core::api;
use aikido_core::error::ApiError;
use serde_json::Value;

use crate::output::{detail_lines, render_ok, str_val, Column, GlobalFlags, Response};

use super::issues::render_failure;
use super::require_session;

const LIST_COLUMNS: &[Column] = &[
    Column { header: "Name", key: "name" },
    Column { header: "Tag", key: "tag" },
    Column { header: "Provider", key: "provider" },
    Column { header: "Status", key: "status" },
];

pub async fn list(
    flags: &GlobalFlags,
    limit: usize,
    name: Option<String>,
    tag: Option<String>,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let containers =
        api::list_containers(&session.client, limit, name.as_deref(), tag.as_deref()).await?;

    let count = containers.len();
    let resp = Response::new(Value::Array(containers))
        .with_summary(format!("{count} containers"))
        .with_count(count);
    render_ok(
        &flags.format(),
        resp,
        LIST_COLUMNS,
        Some(&format_container_line),
    )
    .map_err(render_failure)
}

pub async fn show(flags: &GlobalFlags, container_id: u64) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let container = api::get_container(&session.client, container_id).await?;
    render_ok(
        &flags.format(),
        Response::new(container),
        &[],
        Some(&format_container_detail),
    )
    .map_err(render_failure)
}

pub async fn licenses(flags: &GlobalFlags, container_id: u64) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let packages = api::container_licenses(&session.client, container_id).await?;
    super::repos::render_licenses(flags, packages)
}

fn format_container_line(item: &Value) -> String {
    let name = str_val(item, "name");
    let tag = str_val(item, "tag");
    let name_tag = if tag.is_empty() {
        name
    } else {
        format!("{name}:{tag}")
    };
    format!(
        "  {:<40}  {:<12}  {}",
        name_tag,
        str_val(item, "provider"),
        str_val(item, "status"),
    )
}

fn format_container_detail(item: &Value) -> String {
    detail_lines(&[
        ("Name", str_val(item, "name")),
        ("Provider", str_val(item, "provider")),
        ("Environment", str_val(item, "environment")),
        ("External ID", str_val(item, "external_id")),
    ])
}
