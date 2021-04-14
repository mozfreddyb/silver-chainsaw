//use super::regex::Regex;
//use strum;
//use strum_macros;

pub(crate) mod checktypes;
pub(crate) mod policytypes;
pub mod principal;
mod tests;

use crate::parsing::checktypes::{CheckLine, ContentSecurityCheck, WrappedCheck};
use crate::parsing::policytypes::nsContentPolicyType;
use log::{error, info, warn};

use regex::Regex;
use std::io::BufRead;
use std::str::FromStr;

pub fn parse_contentpolicytype(typestr: &str) -> &'static str {
    let parsed = nsContentPolicyType::from_str(typestr);
    if let Ok(cpt) = parsed {
        <&'static str>::from(cpt)
    } else {
        "TYPE_UNKNOWN"
    }
}

pub fn parsed_content_security_check(
    process_type: ProcessType,
    block: Vec<String>,
) -> Result<ContentSecurityCheck, serde_yaml::Error> {
    let le_block = block.join("\n");
    let deserialized: WrappedCheck = serde_yaml::from_str::<WrappedCheck>(&le_block)?;
    let as_lines: Vec<CheckLine> = deserialized.doContentSecurityCheck;
    let mut check = ContentSecurityCheck::from(as_lines);
    check.process_type = process_type;
    Ok(check)
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ProcessType {
    Child,
    Parent,
    Unknown,
}

pub fn parse_log(
    reader: std::boxed::Box<dyn std::io::BufRead>,
    //    mut outfile: std::boxed::Box<dyn std::io::Write>,
) -> std::io::Result<Vec<ContentSecurityCheck>> {
    const BEGIN_BLOCK: &str = "#DebugDoContentSecurityCheck Begin";
    const END_BLOCK: &str = "#DebugDoContentSecurityCheck End";
    let lines = reader.lines().map(|l| l.unwrap());
    let mut blocks: Vec<ContentSecurityCheck> = vec![];
    let mut current_block: Vec<String> = Vec::with_capacity(30);
    let mut within_block = false;
    let mut linecnt = 0;
    let is_csmlog_line =
        Regex::new(r"\[(Parent|Child) \d+: Main Thread]: (V|D)/CSMLog (.*)").unwrap();
    let mut process_type = ProcessType::Unknown;
    for line in lines {
        // TODO investigate if we can use == instead of contains(). should be cheaper.
        if line == BEGIN_BLOCK {
            linecnt += 1;
            within_block = true;
            continue;
        } else if line == END_BLOCK {
            within_block = false;
            if let Ok(parsed_block) =
                parsed_content_security_check(process_type, current_block.clone())
            {
                blocks.push(parsed_block);
            } else {
                error!(
                    "We had to skip a block, because it was not parsable:\n--\n{}\n--",
                    current_block.join("\n")
                );
            }
            current_block.clear();
            // emit formerly collected block
        }
        if within_block {
            // append to current block
            let captures = is_csmlog_line.captures(&line);
            // 0 = all, 1 = parent/child, 2 = after CSMLog
            if let Some(caps) = captures {
                //let caps = captures.unwrap();
                let process_type_str = caps.get(1).unwrap().as_str();
                process_type = match process_type_str {
                    "Child" => ProcessType::Child,
                    "Parent" => ProcessType::Parent,
                    _ => {
                        warn!(
                            "Noticed unknown string for process type: {}",
                            process_type_str
                        );
                        ProcessType::Unknown
                    }
                };
                let logged_line = caps.get(3).unwrap().as_str();
                current_block.push(String::from(logged_line));
            } else {
                // We are ignoring csmlog lines that aren't part of a security check.
                // can turn this into an info!() logging call, eventually.
                warn!("skipping line that isn't a valid csmlog line: {}", line);
            }
        }
    }
    info!(
        "Finished parsing {} lines and received {} blocks",
        linecnt,
        blocks.len()
    );
    Ok(blocks)
}

//pub fn parse
// FIXME add tests for all parsing cases

// TODO:
// add code & tests to identify & scan security flags (for now, should just take them as literal strings!)
// add code & tests for a checkblock, with an enum like Principal to get blocks
// -- this checkblock should also contain the pid & thread info
// add code & tests to identify a checkblock in the first place

#[cfg(test)]
mod tests_parse_contentpolicytype {
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
#[cfg(test)]
mod tests_parse_lines_into_content_security_check_block {
    use crate::parsing::checktypes::{CheckLine, WrappedCheck};

    use crate::parsing::{parsed_content_security_check, tests, ContentSecurityCheck, ProcessType};

    #[test]
    fn parse_simple_block_manually() {
        let block_slices: Vec<&str> = tests::fixtures::SAMPLE_BLOCK.split('\n').collect();
        let mut block: Vec<String> = Vec::with_capacity(block_slices.len());
        for b in block_slices {
            block.push(b.to_owned());
        }
        let le_block = block.join("\n");
        let deserialized: Result<WrappedCheck, _> = serde_yaml::from_str::<WrappedCheck>(&le_block);
        assert!(deserialized.is_ok());
        let wrapped = deserialized.unwrap();
        let checky: Vec<CheckLine> = wrapped.doContentSecurityCheck;
        let check: ContentSecurityCheck = ContentSecurityCheck::from(checky);
        assert_eq!(check.http_method, Some("POST".to_string()));
    }
    #[test]
    fn test_parse_content_security_check_simple_block() {
        let block_slices: Vec<&str> = tests::fixtures::SAMPLE_BLOCK.split('\n').collect();
        let mut block: Vec<String> = Vec::with_capacity(block_slices.len());
        for b in block_slices {
            block.push(b.to_owned());
        }
        let p = ProcessType::Child;
        let check = parsed_content_security_check(p, block);
        assert!(check.is_ok());
        assert_eq!(check.unwrap().process_type, p);
    }
}

#[cfg(test)]
mod tests_parse_log {
    use crate::parsing::parse_log;
    use std::io::BufReader;
    #[test]
    fn parse_file_incomplete_block() {
        let f = "src/parsing/tests/block-and-incomplete.txt";
        let h = std::fs::File::open(f).unwrap();
        let bufreader = BufReader::new(h);
        let result = parse_log(Box::new(bufreader)).unwrap();
        assert_eq!(result.len(), 2);
        /*for c in result {
            println!("{:?}", c);
        }*/
    }
}
