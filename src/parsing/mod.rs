use super::regex::Regex;
use super::serde_json::{Value, Error};
use super::url::{ParseError, Url};


use std::fs::File;


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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
                let str_len = text.len();
                let inner = &text[21..str_len - 2];
                for value in inner.split(' ') {
                    let p = match parse_into_principal(value) {
                        Ok(innerprincipal) => innerprincipal,
                        Err(_) => return Err("Error parsing inner principal in Expanded Principal"),
                    };
                    principals.push(p);
                }
                Ok(Principal::ExpandedPrincipal(principals))
            } else {
                let url = Url::parse(other);
                if url.is_ok() {
                    Ok(Principal::URLPrincipal(url.unwrap().into_string()))
                } else {
                    Err("Error parsing into principal")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests_pip {
    use parsing::{parse_into_principal, Principal};

    #[test]
    fn parse_http_url() {
        assert_eq!(
            parse_into_principal("http://example.com/"),
            Ok(Principal::URLPrincipal("http://example.com/".to_string()))
        );
    }

    #[test]
    fn parse_about_url() {
        assert_eq!(
            parse_into_principal("about:config"),
            Ok(Principal::URLPrincipal("about:config".to_string()))
        );
    }

    #[test]
    fn parse_null_principal() {
        assert_eq!(
            parse_into_principal("NullPrincipal"),
            Ok(Principal::NullPrincipal)
        );
    }

    #[test]
    fn parse_nullptr_principal() {
        assert_eq!(parse_into_principal("nullptr"), Ok(Principal::NullPtr));
    }

    #[test]
    fn parse_expanded_principal_1() {
        assert_eq!(
            parse_into_principal("[Expanded Principal [https://example.com/]]"),
            Ok(Principal::ExpandedPrincipal(vec![Principal::URLPrincipal(
                "https://example.com/".to_string()
            )]))
        );
    }

    #[test]
    fn parse_expanded_principal_2() {
        assert_eq!(
            parse_into_principal("[Expanded Principal [moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/ https://example.com/]]"),
            Ok(Principal::ExpandedPrincipal(vec![
                Principal::URLPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string()),
                Principal::URLPrincipal("https://example.com/".to_string())]))
        );
    }

    #[test]
    fn parse_expanded_principal_2_preserves_order() {
        assert_eq!(
            parse_into_principal("[Expanded Principal [https://example.com/ moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/]]"),
            Ok(Principal::ExpandedPrincipal(vec![
                Principal::URLPrincipal("https://example.com/".to_string()),
                Principal::URLPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string())]))
        );
    }
}




#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ProcessType {
    ParentProcess,
    ChildProcess,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ContentSecurityCheck {
    channeluri: String,
    http_method: String,
    loadingprincipal: String, // Principal,
    triggeringprincipal: String, // Principal,
    principaltoinherit: String, // Principal,
    redirectchain: Vec<String>,
    internalcontentpolicytype: u64,
    externalcontentpolicytype: u64,
    upgradeinsecurerequests: bool,
    initalsecuritychecksdone: bool,
    enforcesecurity: bool,
    securityflags: Vec<String>,
}



pub fn parse_log(text: &str, outfile: File) {
    let lines = text.split('\n');
    let mut blocks: Vec<ContentSecurityCheck> = vec![];
    let mut current_block: Vec<String> = vec![];
    let is_csmlog_line = Regex::new(r"\[(Parent|Child) \d+: Main Thread]: \w+/CSMLog (.*)").unwrap();
    let needs_quotes = Regex::new(r"\s+(?P<key>[^:>]+):\s+(?P<value>\S+)").unwrap();
    let mut collected_security_flags: Vec<String> = vec![];
    let mut collected_redirect_chain: Vec<String> = vec![];
    for line in lines {
        let captures = is_csmlog_line.captures(line);
        // 0 = all, 1 = parend/child, 2 = after CSMLog
        if captures.is_some() {
            let logged_line = captures.unwrap().get(2).unwrap().as_str(); //XXX
            let quotes_required = needs_quotes.captures(logged_line);
            if quotes_required.is_some() {
                let caps= quotes_required.unwrap();
                let key = caps.get(1).unwrap().as_str(); //XXX
                let value = caps.get(2).unwrap().as_str(); //XXX
                // numeric value?
                let is_numeric = value.parse::<u64>();
                                // quote both:
                let quoted_line : String;
                if is_numeric.is_ok() || value == "true" || value == "false" {
                    quoted_line = format!("\"{}\": {}", key.to_lowercase().replace(" ","_"), value);
                } else {
                    quoted_line = format!("\"{}\": \"{}\"", key.to_lowercase().replace(" ","_"), value);
                }
                current_block.push(quoted_line);
            } else if line.ends_with('}') {
                // next block
                let secflags = format!("\"securityflags\": [{}]", collected_security_flags.join(","));
                current_block.push(secflags);
                let redirects = format!("\"redirectchain\": [{}]", collected_redirect_chain.join(","));
                current_block.push(redirects);

                let json = format!("{{  {}  }}", current_block.join(","));
                //println!("JSON attempt {}", &json);
                let parsed_json = serde_json::from_str(&json);
                if parsed_json.is_ok() {
                    let block = parsed_json.unwrap();
                    println!("\n\nBlock {:?}", &block);
                    blocks.push(block);
                    current_block = vec![];
                    collected_security_flags = vec![];
                    collected_redirect_chain = vec![];
                    }
                else {
                    panic!("Couldnt parse json. boo. {:?}", parsed_json);
                }
            } else {
                // RedirectChain and securityFlags have items below, cant just be quoted values.
                // need to collect array values
                if logged_line.contains("->:") {
                    collected_redirect_chain.push(format!("\"{}\"", logged_line.replace("->:","").trim()));
                }
                else if logged_line.contains("SEC_") {
                    collected_security_flags.push(format!("\"{}\"", logged_line.trim()));
            }
        }
    }

    //blocks
}



}

//pub fn parse
// FIXME add tests for all parsing cases

// TODO:
// add code & tests to identify & scan security flags (for now, should just take them as literal strings!)
// add code & tests for a checkblock, with an enum like Principal to get blocks
// -- this checkblock should also contain the pid & thread info
// add code & tests to identify a checkblock in the first place
