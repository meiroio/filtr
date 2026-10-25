use super::Proposal;
use crate::policy::Report;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) const MAX_INPUT_BYTES: usize = 128 * 1024;

#[derive(Clone)]
pub(super) struct Batch {
    pub input: String,
    bases: BTreeSet<(usize, String)>,
    pub(super) components: BTreeSet<usize>,
}

impl Batch {
    pub fn includes_component(&self, index: usize) -> bool {
        self.components.contains(&index)
    }

    pub fn includes(&self, proposal: &Proposal) -> bool {
        self.bases
            .contains(&(proposal.component_index, proposal.basis.clone()))
    }
}

struct Pending {
    input: Value,
    bases: BTreeSet<(usize, String)>,
    bytes: usize,
}

impl Pending {
    fn new(envelope: &Value) -> Result<Self> {
        Ok(Self {
            input: envelope.clone(),
            bases: BTreeSet::new(),
            bytes: serde_json::to_vec(envelope)?.len(),
        })
    }

    fn finish(self) -> Result<Batch> {
        let input = serde_json::to_string(&self.input)?;
        ensure!(input.len() <= MAX_INPUT_BYTES, "AI batch exceeds 128 KiB");
        Ok(Batch {
            components: self.input["components"]
                .as_array()
                .context("AI batch components must be an array")?
                .iter()
                .filter_map(|c| c["component_index"].as_u64().map(|i| i as usize))
                .collect(),
            input,
            bases: self.bases,
        })
    }
}

#[cfg(test)]
pub(super) fn plan(report: &Report) -> Result<Vec<Batch>> {
    plan_missing(report, &(0..report.components.len()).collect())
}

pub(super) fn cached(report: &Report, index: usize) -> Batch {
    Batch {
        input: String::new(),
        components: [index].into(),
        bases: report.components[index]
            .active_rules
            .iter()
            .map(|id| (index, id.clone()))
            .collect(),
    }
}

pub(super) fn plan_missing(report: &Report, missing: &BTreeSet<usize>) -> Result<Vec<Batch>> {
    let envelope = json!({"total_components":report.components.len(), "components":[], "curated_rules":report.active_rules});
    let mut pending = Pending::new(&envelope)?;
    let mut batches = Vec::new();
    for &index in missing {
        let item = &report.components[index];
        let mut component = serde_json::to_value(item)?;
        component["component_index"] = json!(index);
        let bytes = serde_json::to_vec(&component)?.len() + 1;
        if pending.bytes + bytes > MAX_INPUT_BYTES
            && !pending.input["components"]
                .as_array()
                .context("AI batch components must be an array")?
                .is_empty()
        {
            batches.push(pending.finish()?);
            pending = Pending::new(&envelope)?;
        }
        ensure!(
            pending.bytes + bytes <= MAX_INPUT_BYTES,
            "one AI component exceeds 128 KiB"
        );
        pending.bytes += bytes;
        pending
            .bases
            .extend(item.active_rules.iter().map(|id| (index, id.clone())));
        pending.input["components"]
            .as_array_mut()
            .context("AI batch components must be an array")?
            .push(component);
    }
    if !pending.input["components"]
        .as_array()
        .context("AI batch components must be an array")?
        .is_empty()
    {
        batches.push(pending.finish()?);
    }
    ensure!(batches.len() <= 512, "AI review exceeds 512 batches");
    Ok(batches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batching_preserves_every_global_component_index_and_rejects_unsupplied_bases() {
        let mut packages: Vec<_> = (0..3000)
            .map(|i| json!({"purl":format!("pkg:npm/package-{i}@1.0.0")}))
            .collect();
        packages.push(json!({"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}));
        let bytes = serde_json::to_vec(&json!({"format":"filtr-1","packages":packages})).unwrap();
        let policy = crate::policy::Policy::compile(
            crate::sbom::parse(&bytes).unwrap(),
            &crate::policy::Catalog::bundled().unwrap(),
        )
        .unwrap();
        let batches = plan(&policy.report).unwrap();
        assert!(batches.len() > 1);
        let mut indexes = BTreeSet::new();
        for batch in &batches {
            assert!(batch.input.len() <= MAX_INPUT_BYTES);
            let input: Value = serde_json::from_str(&batch.input).unwrap();
            indexes.extend(
                input["components"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| c["component_index"].as_u64().unwrap()),
            );
            assert!(!batch.includes(&Proposal {
                component_index: 0,
                basis: "invented".into(),
                action: "deny_all".into(),
                patterns: vec![],
                reason: "unsupported".into()
            }));
        }
        assert_eq!(indexes, (0..3001).collect());
        let proposal = Proposal {
            component_index: 3000,
            basis: "log4shell-lookups".into(),
            action: "deny_all".into(),
            patterns: vec![],
            reason: "Only the batch containing this global component may propose this rule.".into(),
        };
        assert!(!batches.first().unwrap().includes(&proposal));
        assert!(batches.last().unwrap().includes(&proposal));
    }
}
