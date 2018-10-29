pub fn parse_into_contentpolicytype(id: usize) -> &'static str {
    let policytypes = include!("policytypes.in");
    if id < policytypes.len() {
        policytypes[id]
    } else {
        "TYPE_UNKNOWN(what?)"
    }
}

#[cfg(test)]
mod tests {
    use parsing::parse_into_contentpolicytype;

    #[test]
    fn policy_type_basic() {
        assert_eq!(parse_into_contentpolicytype(9), "TYPE_XBL");
    }

    #[test]
    fn policy_type_11_is_aliased() {
        assert_eq!(
            parse_into_contentpolicytype(11),
            "TYPE_XMLHTTPREQUEST_OR_TYPE_DATAREQUEST"
        );
    }

    #[test]
    fn policy_type_array_oob() {
        assert_eq!(parse_into_contentpolicytype(999), "TYPE_UNKNOWN");
    }

    #[test]
    fn policy_type_array_end() {
        assert_eq!(parse_into_contentpolicytype(45), "TYPE_UNKNOWN");
    }
}

#[derive(Debug, PartialEq)]
pub enum Principal {
    URLPrincipal(String),
    ///XXX decide whether we need URL parsing/validation
    ExpandedPrincipal(Vec<Principal>),
    SystemPrincipal,
    NullPrincipal,
    NullPtr,
}

pub fn parse_into_principal(text: &str) -> Result<Principal, &'static str> {
    match text {
        "SystemPrincipal" => Ok(Principal::SystemPrincipal),
        "NullPrincipal" => Ok(Principal::NullPrincipal),
        "nullptr" => Ok(Principal::NullPtr),
        other => {
            // parse URL
            //if starts with [Expa]
            if text.starts_with("[Expanded Principal [") && text.ends_with("]]") {
                let mut principals: Vec<Principal> = vec![];
                let strlen = text.len();
                let inner = &text[21..strlen - 2];
                for value in inner.split(' ') {
                    let p = parse_into_principal(value);
                    principals.push(p);
                }
                return Ok(Principal::ExpandedPrincipal(principals));
            }
            Err("Error parsing into principal")
        }
    }
}

#[cfg(test)]
mod tests_pip {
    use parsing::{parse_into_principal, Principal};

    #[test]
    fn parse_http_url() {
        assert_eq!(
            parse_into_principal("http://example.com/").unwrap(),
            Principal::URLPrincipal("http://example.com/".to_string())
        );
    }

    #[test]
    fn parse_about_url() {
        assert_eq!(
            parse_into_principal("about:config").unwrap(),
            Principal::URLPrincipal("about:config".to_string())
        );
    }

    #[test]
    fn parse_null_principal() {
        assert_eq!(
            parse_into_principal("NullPrincipal").unwrap(),
            Principal::NullPrincipal
        );
    }

    #[test]
    fn parse_nullptr_principal() {
        assert_eq!(parse_into_principal("nullptr").unwrap(), Principal::NullPtr);
    }

    #[test]
    fn parse_expanded_principal_1() {
        assert_eq!(
            parse_into_principal("[Expanded Principal [https://example.com]]").unwrap(),
            Principal::ExpandedPrincipal(vec![Principal::URLPrincipal(
                "https://example.com".to_string()
            )])
        );
    }

    #[test]
    fn parse_expanded_principal_2() {
        assert_eq!(
            parse_into_principal("[Expanded Principal [moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/ https://example.com]]").unwrap(),
            Principal::ExpandedPrincipal(vec![
                Principal::URLPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string()),
                Principal::URLPrincipal("https://example.com".to_string())])
        );
    }

    #[test]
    fn parse_expanded_principal_2_preserves_order() {
        assert_eq!(
            parse_into_principal("[Expanded Principal [https://example.com moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![
                Principal::URLPrincipal("https://example.com".to_string()),
                Principal::URLPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string())])
        );
    }
}

// FIXME add tests for all parsing cases

// TODO:
// add code & tests to identify & scan security flags (for now, should just take them as literal strings!)
// add code & tests for a checkblock, with an enum like Principal to get blocks
// -- this checkblock should also contain the pid & thread info
// add code & tests to identify a checkblock in the first place
