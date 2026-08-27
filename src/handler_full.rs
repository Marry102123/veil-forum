use axum::{extract::{Path, Query, State}, response::{Html, IntoResponse, Redirect}, http::{StatusCode, header}, Form};
use serde::Deserialize;
use std::collections::HashMap;
use crate::store::Store;
use crate::pow::{self, Manager, Scope};
use crate::markdown;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub pow: Manager,
}

#[derive(Deserialize)]
pub struct Pagination { pub page: Option<i64> }
#[derive(Deserialize)]
pub struct SearchQuery { pub q: Option<String>, pub page: Option<i64> }

pub async fn home(State(s): State<AppState>) -> impl IntoResponse {
    let boards = s.store.list_boards().await.unwrap_or_default();
    Html(format!("<h1>Home - {} boards</h1>", boards.len()))
}
