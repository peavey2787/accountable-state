use zk_sdk::predicate::Commitment;

const VERSION: u8 = 1;
const MAX_PROOF: usize = 16 * 1024 * 1024;

pub(crate) struct Package {
    pub old: Vec<Commitment>,
    pub new: Vec<Commitment>,
    pub proof: Vec<u8>,
}

pub(crate) fn encode(old: &[Commitment], new: &[Commitment], proof: &[u8]) -> Vec<u8> {
    let mut out = vec![VERSION, old.len() as u8];
    for c in old.iter().chain(new) {
        let text = c.to_text();
        out.push(text.len() as u8);
        out.extend_from_slice(text.as_bytes());
    }
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    out.extend_from_slice(proof);
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        (self.0.len() >= n).then(|| {
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            head
        })
    }

    fn commitment(&mut self) -> Option<Commitment> {
        let len = usize::from(*self.take(1)?.first()?);
        let text = std::str::from_utf8(self.take(len)?).ok()?;
        Commitment::from_text(text).ok()
    }

    fn list(&mut self, n: usize) -> Option<Vec<Commitment>> {
        (0..n).map(|_| self.commitment()).collect()
    }
}

pub(crate) fn decode(bytes: &[u8]) -> Option<Package> {
    let mut r = Reader(bytes);
    let head = r.take(2)?;
    if head[0] != VERSION || head[1] == 0 {
        return None;
    }
    let n = usize::from(head[1]);
    let old = r.list(n)?;
    let new = r.list(n)?;
    let len = u32::from_le_bytes(r.take(4)?.try_into().ok()?) as usize;
    if len > MAX_PROOF {
        return None;
    }
    let proof = r.take(len)?.to_vec();
    r.0.is_empty().then_some(Package { old, new, proof })
}
