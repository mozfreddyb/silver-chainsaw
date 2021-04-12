//use super::regex::Regex;
//use strum;
//use strum_macros;

mod policytypes;
pub mod principal;
use crate::parsing::policytypes::nsContentPolicyType;
use std::str::FromStr;

//use std::io::{ErrorKind, Write};

pub fn parse_contentpolicytype(typestr: &str) -> &'static str {
    let parsed = nsContentPolicyType::from_str(typestr);
    if let Ok(cpt) = parsed {
        <&'static str>::from(cpt)
    } else {
        "TYPE_UNKNOWN"
    }
}

#[cfg(test)]
mod tests {
    use crate::parsing::parse_contentpolicytype;

    #[test]
    fn policy_type_basic() {
        assert_eq!(parse_contentpolicytype("TYPE_DOCUMENT"), "TYPE_DOCUMENT");
    }

    #[test]
    fn policy_type_invalid_string() {
        assert_eq!(parse_contentpolicytype("blergh"), "TYPE_UNKNOWN");
    }

    #[test]
    fn policy_type_empty_string() {
        assert_eq!(parse_contentpolicytype(""), "TYPE_UNKNOWN");
    }

    #[test]
    fn policy_type_as_number_str() {
        assert_eq!(parse_contentpolicytype("11"), "TYPE_UNKNOWN");
    }
}

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct doContentSecurityCheck {
    //processtype: String,
    channelURI: String,
    httpMethod: Option<String>, // only shown for http channels
    loadingPrincipal: principal::Principal,
    triggeringPrincipal: principal::Principal,
    principalToInherit: principal::Principal,
    redirectChain: Vec<String>, // key always present might be be empty value
    internalContentPolicyType: String,
    externalContentPolicyType: String,
    upgradeInsecureRequests: bool,
    initalSecurityChecksDone: bool,
    allowDeprecatedSystemRequests: bool,
    CSP: Vec<String>, // key always present, might be empty value
    securityflags: Vec<String>,
}

pub fn unprefixed_to_yaml(
    text: &str,
    _outfile: std::boxed::Box<dyn std::io::Write>,
) -> Result<(), serde_yaml::Error> {
    let lines = text.split('\n');
    let mut block = String::new();
    let mut scanning = false;
    for line in lines {
        if line == "#DebugDoContentSecurityCheck Begin" {
            scanning = true;
        }
        if line == "#DebugDoContentSecurityCheck End" {
            //let y: Result<doContentSecurityCheck, serde_yaml::Error> = serde_yaml::from_str(&block);
            block.clear();
            scanning = false;
        }
        if scanning {
            block += line;
        }
    }
    Ok(())
}

/*pub fn parse_log(
    text: &str,
    verbosity: u8,
    mut outfile: std::boxed::Box<dyn std::io::Write>,
) -> std::io::Result<()> {
    let lines = text.split('\n');
    let mut blocks: Vec<doContentSecurityCheck> = vec![];
    let mut current_block: Vec<String> = vec![];
    let is_csmlog_line =
        Regex::new(r"\[(Parent|Child) \d+: Main Thread]: \w+/CSMLog (.*)").unwrap();
    let needs_quotes = Regex::new(r"\s+(?P<key>[^:>]+):\s+(?P<value>.+)").unwrap();
    // used [a-zA-Z0-9?&#:/.\-_ \[\]] instead of .+ for value, looked to brittle.
    let mut collected_security_flags: Vec<String> = vec![];
    let mut collected_redirect_chain: Vec<String> = vec![];
    let mut collected_csp: Vec<String> = vec![];
    let mut processtype: &str;
    for line in lines {
        let captures = is_csmlog_line.captures(line);
        // 0 = all, 1 = parend/child, 2 = after CSMLog
        if captures.is_some() {
            let caps = captures.unwrap();
            processtype = caps.get(1).unwrap().as_str();
            let logged_line = caps.get(2).unwrap().as_str(); //XXX
            let quotes_required = needs_quotes.captures(logged_line);
            if quotes_required.is_some() {
                let caps = quotes_required.unwrap();
                let key = caps.get(1).unwrap().as_str(); //XXX
                let normalized_key = key.to_lowercase().replace(" ", "_");
                let value = caps.get(2).unwrap().as_str(); //XXX
                                                           // numeric value?
                let is_numeric = value.parse::<usize>();
                // enquote both:
                let enquoted_line = if is_numeric.is_ok() {
                    if normalized_key.ends_with("contentpolicytype") {
                        format!(
                            "\"{}\": \"{}\"",
                            normalized_key,
                            parse_id_into_contentpolicytype(is_numeric.unwrap())
                        )
                    } else {
                        format!("\"{}\": {}", normalized_key, value)
                    }
                } else if value == "true" || value == "false" {
                    format!("\"{}\": {}", normalized_key, value)
                } else {
                    format!("\"{}\": \"{}\"", normalized_key, value)
                };
                current_block.push(enquoted_line);
            } else if logged_line == "}" {
                current_block.push(format!("\"processtype\": \"{}\"", processtype));
                // next block
                let secflags = format!(
                    "\"securityflags\": [{}]",
                    collected_security_flags.join(",")
                );
                current_block.push(secflags);

                let redirects = format!(
                    "\"redirectchain\": [{}]",
                    collected_redirect_chain.join(",")
                );
                current_block.push(redirects);

                let csp = format!("\"csp\": [{}]", collected_csp.join(","));
                current_block.push(csp);

                let json = format!("{{  {}  }}", current_block.join(","));
                //eprintln!("JSON attempt {}", &json);
                let parsed_json = serde_json::from_str(&json);
                if parsed_json.is_ok() {
                    let block = parsed_json.unwrap();
                    //eprintln!("\n\nBlock {:?}", &block);
                    blocks.push(block);
                    current_block = vec![];
                    collected_security_flags = vec![];
                    collected_redirect_chain = vec![];
                    collected_csp = vec![];
                } else {
                    eprintln!("this should be json {}", &json);
                    panic!("Couldnt parse json: {:?}", parsed_json);
                }
            } else if logged_line.contains("->:") {
                // RedirectChain and securityFlags have items below, cant just be quoted values.
                // need to collect array values
                collected_redirect_chain
                    .push(format!("\"{}\"", logged_line.replace("->:", "").trim()));
            } else if logged_line.contains("SEC_") {
                collected_security_flags.push(format!("\"{}\"", logged_line.trim()));
            } else if logged_line.starts_with("    ") {
                //FIXME dangerous pattern. get smarter.
                collected_csp.push(format!("\"{}\"", logged_line.trim()));
            }
        }
    }
    let blocks_as_json = serde_json::to_string(&blocks).unwrap();
    //println!("Finished parsing {} blocks.\nWritten to parsed.json.", blocks.len());
    if verbosity >= 1 {
        eprintln!("{:?}", blocks_as_json);
    }

    let bytes = blocks_as_json.as_bytes();
    match outfile.write(bytes) {
        Ok(size) if size == bytes.len() => Ok(()),
        Ok(0) | Ok(3) => Err(std::io::Error::new(
            ErrorKind::WriteZero,
            "Wrote only 0 bytes",
        )),
        Ok(_) => Err(std::io::Error::new(
            ErrorKind::Other,
            "Couldnt write file completely",
        )),
        Err(e) => Err(e),
    }
}*/

//pub fn parse
// FIXME add tests for all parsing cases

// TODO:
// add code & tests to identify & scan security flags (for now, should just take them as literal strings!)
// add code & tests for a checkblock, with an enum like Principal to get blocks
// -- this checkblock should also contain the pid & thread info
// add code & tests to identify a checkblock in the first place
