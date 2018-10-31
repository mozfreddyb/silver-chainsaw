use std::str::FromStr;
use std::fmt;
use super::regex::Regex;
use super::serde_json::{Value, Error};
use super::serde::de::{Deserialize, Deserializer, Visitor, Unexpected};
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

#[derive(Debug, PartialEq, Serialize)]
pub enum Principal {
    URLPrincipal(String),
    ///XXX decide whether we need URL parsing/validation
    ExpandedPrincipal(Vec<Principal>),
    SystemPrincipal,
    NullPrincipal,
    NullPtr,
}

impl<'de> Deserialize<'de> for Principal {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Principal, D::Error>
        where
            D: Deserializer<'de>,
    {
        struct PrincipalVisitor;

        impl<'de> Visitor<'de> for PrincipalVisitor {
            type Value = Principal;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON Principal")
            }

            fn visit_str<E>(self, value: &str) -> Result<Principal, E>
                where
                    E: serde::de::Error,
            {
                //Principal::from_str(value)
                match Principal::from_str(value) {
                    Ok(p) => Ok(p),
                    Err(e) => {
                        println!("err {}", e);
                        Err(serde::de::Error::custom("not a JSON Principal"))
                    }
                }
            }

            /*#[cfg(feature = "arbitrary_precision")]
            #[inline]
            fn visit_map<V>(self, mut visitor: V) -> Result<Principal, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let value = visitor.next_key::<PrincipalKey>()?;
                if value.is_none() {
                    return Err(de::Error::invalid_type(Unexpected::Map, &self));
                }
                let v: PrincipalFromString = visitor.next_value()?;
                Ok(v.value)
            }*/
        }

        deserializer.deserialize_any(PrincipalVisitor)
    }
}

impl FromStr for Principal {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> { // serde::de::Error
        match text {
            "SystemPrincipal" => Ok(Principal::SystemPrincipal),
            "NullPrincipal" => Ok(Principal::NullPrincipal),
            "nullptr" => Ok(Principal::NullPtr),
            prin_str => {
                // parse URL
                //if starts with [Expa]
                if prin_str.starts_with("[Expanded Principal [") && prin_str.ends_with("]]") {
                    let mut principals: Vec<Principal> = vec![];
                    let str_len = prin_str.len();
                    let inner = &prin_str[21..str_len - 2];
                    for value in inner.split(' ') {
                        let p = Principal::from_str(value);
                        if p.is_ok() {
                            principals.push(p.unwrap());
                        } else {
                            panic!("Error parsing inner principal in Expanded Principal: {}", &value);
                        }
                    }
                    Ok(Principal::ExpandedPrincipal(principals))
                } else {
                    let url = Url::parse(prin_str);
                    if url.is_ok() {
                        Ok(Principal::URLPrincipal(url.unwrap().into_string()))
                    } else {
                        Err(serde::de::Error::invalid_type(Unexpected::Str("Error parsing into principal"), &prin_str))
                    }
                }
            }
        }
    }
}


#[cfg(test)]
mod tests_principal_from_str {
    use parsing::Principal;
    use std::str::FromStr;

    #[test]
    fn parse_http_url() {
        assert_eq!(
            Principal::from_str("http://example.com/").unwrap(),
            Principal::URLPrincipal("http://example.com/".to_string())
        );
    }

    #[test]
    fn parse_about_url() {
        assert_eq!(
            Principal::from_str("about:config").unwrap(),
            Principal::URLPrincipal("about:config".to_string())
        );
    }

    #[test]
    fn parse_null_principal() {
        assert_eq!(
            Principal::from_str("NullPrincipal").unwrap(),
            Principal::NullPrincipal
        );
    }

    #[test]
    fn parse_nullptr_principal() {
        assert_eq!(Principal::from_str("nullptr").unwrap(), Principal::NullPtr);
    }

    #[test]
    fn parse_expanded_principal_1() {
        assert_eq!(
            Principal::from_str("[Expanded Principal [https://example.com/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![Principal::URLPrincipal(
                "https://example.com/".to_string()
            )])
        );
    }

    #[test]
    fn parse_expanded_principal_2() {
        assert_eq!(
            Principal::from_str("[Expanded Principal [moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/ https://example.com/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![
                Principal::URLPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string()),
                Principal::URLPrincipal("https://example.com/".to_string())])
        );
    }

    #[test]
    fn parse_expanded_principal_2_preserves_order() {
        assert_eq!(
            Principal::from_str("[Expanded Principal [https://example.com/ moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![
                Principal::URLPrincipal("https://example.com/".to_string()),
                Principal::URLPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string())])
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
    loadingprincipal: Principal,
    triggeringprincipal: Principal,
    principaltoinherit: Principal,
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
    let needs_quotes = Regex::new(r"\s+(?P<key>[^:>]+):\s+(?P<value>.+)").unwrap();
    // used [a-zA-Z0-9?&#:/.\-_ \[\]] instead of .+ for value, looked to brittle.
    let mut collected_security_flags: Vec<String> = vec![];
    let mut collected_redirect_chain: Vec<String> = vec![];
    for line in lines {
        let captures = is_csmlog_line.captures(line);
        // 0 = all, 1 = parend/child, 2 = after CSMLog
        if captures.is_some() {
            let logged_line = captures.unwrap().get(2).unwrap().as_str(); //XXX
            let quotes_required = needs_quotes.captures(logged_line);
            if quotes_required.is_some() {
                let caps = quotes_required.unwrap();
                let key = caps.get(1).unwrap().as_str(); //XXX
                let value = caps.get(2).unwrap().as_str(); //XXX
                // numeric value?
                let is_numeric = value.parse::<u64>();
                // quote both:
                let quoted_line = if is_numeric.is_ok() || value == "true" || value == "false" {
                    format!("\"{}\": {}", key.to_lowercase().replace(" ", "_"), value)
                } else {
                    format!("\"{}\": \"{}\"", key.to_lowercase().replace(" ", "_"), value)
                };
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
                    println!("{}", serde_json::to_string(&block).unwrap());
                    //println!("\n\nBlock {:?}", &block);
                    blocks.push(block);
                    current_block = vec![];
                    collected_security_flags = vec![];
                    collected_redirect_chain = vec![];
                } else {
                    panic!("Couldnt parse json: {:?}", parsed_json);
                }
            } else if logged_line.contains("->:") {
                // RedirectChain and securityFlags have items below, cant just be quoted values.
                // need to collect array values
                collected_redirect_chain.push(format!("\"{}\"", logged_line.replace("->:", "").trim()));
            } else if logged_line.contains("SEC_") {
                collected_security_flags.push(format!("\"{}\"", logged_line.trim()));
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
