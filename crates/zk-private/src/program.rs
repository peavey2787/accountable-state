use gv_core::Digest;
use sha2::{Digest as _, Sha256};
use zk_sdk::predicate::{Op, Rule};

/// Rules the context rule and the root bindings may add to.
pub const MAX_APP_RULES: usize = 7;

/// The pinned relation: the application rules over the user fields, and the violation code the
/// claims of this program carry. The program id commits to both and to the proof system's
/// version, so a verifier cannot be handed a weaker relation.
#[derive(Clone, Debug)]
pub struct Program {
    fields: usize,
    rules: Vec<Rule>,
    violation_code: u16,
    id: Digest,
}

impl Program {
    /// `fields` is the number of user fields (the context slot is added after them). Rules may
    /// only mention user fields.
    pub fn new(fields: usize, rules: Vec<Rule>, violation_code: u16) -> Result<Self, String> {
        if fields == 0 || fields > usize::from(u8::MAX) {
            return Err("a state needs between 1 and 255 fields".into());
        }
        if rules.is_empty() || rules.len() > MAX_APP_RULES {
            return Err(format!("a program needs 1 to {MAX_APP_RULES} rules"));
        }
        if let Some(bad) = rules.iter().find_map(|r| out_of_range(r, fields)) {
            return Err(format!(
                "rule names field {bad}, but the state has {fields}"
            ));
        }
        let id = identify(fields, &rules, violation_code)?;
        Ok(Self {
            fields,
            rules,
            violation_code,
            id,
        })
    }

    pub fn id(&self) -> Digest {
        self.id
    }

    pub fn violation_code(&self) -> u16 {
        self.violation_code
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn fields(&self) -> usize {
        self.fields
    }

    /// The rules plus the context rule for the slot at `slot` with value `tag`.
    pub(crate) fn rules_with_context(&self, slot: usize, tag: u128) -> Vec<Rule> {
        let mut all = self.rules.clone();
        all.push(Rule::Ensure {
            field: slot,
            op: Op::Eq,
            bound: tag.into(),
        });
        all
    }
}

fn mentioned(rule: &Rule) -> Vec<usize> {
    match rule {
        Rule::Compare { field, .. }
        | Rule::Add { field, .. }
        | Rule::Sub { field, .. }
        | Rule::Require { field, .. }
        | Rule::Ensure { field, .. } => vec![*field],
        Rule::Conserve { fields, .. } => fields.clone(),
    }
}

fn out_of_range(rule: &Rule, fields: usize) -> Option<usize> {
    mentioned(rule).into_iter().find(|f| *f >= fields)
}

fn identify(fields: usize, rules: &[Rule], violation_code: u16) -> Result<Digest, String> {
    let mut h = Sha256::new();
    h.update(b"gv-zk-private/program/v1");
    h.update((fields as u64).to_le_bytes());
    h.update(violation_code.to_le_bytes());
    for rule in rules {
        let text = serde_json::to_string(rule).map_err(|e| e.to_string())?;
        h.update((text.len() as u64).to_le_bytes());
        h.update(text.as_bytes());
    }
    Ok(h.finalize().into())
}
