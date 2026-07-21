// implementer fills in TunnelSet above

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let set = TunnelSet::new();
        assert!(set.epochs().is_empty());
        assert!(set.get(0).is_none());
    }
}
