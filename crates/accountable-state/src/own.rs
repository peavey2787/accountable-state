use std::collections::VecDeque;

/// My own submitted controls not yet covered by a certified epoch. The pipeline reads them to
/// sign batches and answer challenges; certification releases them.
pub(crate) struct OwnInputs {
    from: u64,
    controls: VecDeque<u16>,
}

impl OwnInputs {
    pub(crate) fn new(from: u64) -> Self {
        Self {
            from,
            controls: VecDeque::new(),
        }
    }
    pub(crate) fn push(&mut self, control: u16) {
        self.controls.push_back(control);
    }
    /// Controls for ticks `from..to`, or `None` if any of them is unknown or released.
    pub(crate) fn range(&self, from: u64, to: u64) -> Option<Vec<u16>> {
        let end = self.from + self.controls.len() as u64;
        if from < self.from || to > end || from > to {
            return None;
        }
        Some(
            (from..to)
                .map(|t| self.controls[(t - self.from) as usize])
                .collect(),
        )
    }
    /// Forget everything before tick `end`.
    pub(crate) fn release_before(&mut self, end: u64) {
        while self.from < end && self.controls.pop_front().is_some() {
            self.from += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OwnInputs;

    #[test]
    fn ranges_are_exact_and_released_ticks_are_gone() {
        let mut o = OwnInputs::new(10);
        for c in [1, 2, 3, 4] {
            o.push(c);
        }
        assert_eq!(o.range(11, 13), Some(vec![2, 3]));
        assert_eq!(o.range(9, 11), None);
        assert_eq!(o.range(12, 15), None);
        assert_eq!(o.range(13, 12), None);
        o.release_before(12);
        assert_eq!(o.range(11, 12), None);
        assert_eq!(o.range(12, 14), Some(vec![3, 4]));
        o.release_before(100);
        assert_eq!(o.range(14, 14), Some(vec![]));
    }
}
