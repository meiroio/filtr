use crate::policy::Action;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub origin: &'static str,
    pub package: String,
    pub version: Option<String>,
    pub basis: String,
    pub cves: Vec<String>,
    pub action: Action,
    pub description: String,
    pub source: String,
}
