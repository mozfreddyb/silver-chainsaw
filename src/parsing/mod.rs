pub fn parse_into_contentpolicytype(id: usize) -> &'static str {
    let policytypes = include!("policytypes.in");
    if id < policytypes.len() {
        policytypes[id]
    } else {
        "TYPE_UNKNOWN"
    }
}

#[cfg(test)]
mod tests {
    use parsing::typefromid;
    #[test]
    fn policy_type_basic() {
        assert_eq!(typefromid(9), "TYPE_XBL");
    }
    #[test]
    fn policy_type_11_is_aliased() {
        assert_eq!(typefromid(11), "TYPE_XMLHTTPREQUEST_OR_TYPE_DATAREQUEST");
    }

    #[est]
    fn policy_type_array_oob() {
        assert_eq!(typefromid(999), "TYPE_UNKNOWN");
    }
    #[test]
    fn policy_type_array_end() {
        assert_eq!(typefromid(45), "TYPE_UNKNOWN");
    }
}

enum Principal {
    URLPrincipal(&str),
    ExpandedPrincipal(&str),
    SystemPrincipal,
    NullPrincipal,
    NullPtr,
}

pub fn parseprincipal(text: &str) -> Principal {
    match text {
        "SystemPrincipal" => Principal::SystemPrincipal,
        "NullPrincipal" => Principal::NullPrincipal,
        "nullptr" => Principal::NullPrincipal,
        other => {
            // parse URL
            //if starts with [Expa]
            if (text.starts_with("[Expan")) {
                Principal::ExpandedPrincipal(other)
            }
            Principal::URLPrincipal(other)
        }
    }
}
///FIXME add tests for all parsing cases


// TODO:
// add code & tests to identify & scan security flags (for now, should just take them as literal strings!)
// add code & tests for a checkblock, with an enum like Principal to get blocks
// -- this checkblock should also contain the pid & thread info
// add code & tests to identify a checkblock in the first place


