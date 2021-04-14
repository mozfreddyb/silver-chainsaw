#[macro_use]
extern crate serde_derive;

extern crate getopts;
extern crate regex;
extern crate serde;
extern crate serde_json;
extern crate url;

use crate::parsing::checktypes::ContentSecurityCheck;
use crate::parsing::parse_log;
use crate::parsing::policytypes::nsContentPolicyType;
use crate::parsing::principal::Principal;

use getopts::Options;
use log::info;
use std::env;
use std::io;
use std::io::BufReader;

mod parsing;

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() -> io::Result<()> {
    env_logger::init();
    // arg parsing
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("v", "verbose", "give more verbose output");
    opts.optflag("h", "help", "print usage info");
    opts.optopt(
        "d",
        "dir",
        "read files matching moz_log from this directory",
        "DIRECTORY",
    );
    opts.optmulti("i", "input", "read from these files", "INFILE");
    //let mut verbosity_lvl = 0;
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => panic!("{}", e.to_string()),
    };
    if matches.opt_present("h") {
        print_usage(&program, &opts);
        return Ok(());
    }
    let mut happyblocks: Vec<ContentSecurityCheck> = vec![];

    let diropt = matches.opt_str("d");

    if let Some(dirname) = diropt {
        println!("Scanning {}", dirname);
        for entry in std::fs::read_dir(dirname)? {
            if let Ok(entry) = entry {
                if let Ok(file_type) = entry.file_type() {
                    // Now let's show our entry's file type!
                    if file_type.is_file() {
                        let file_name = entry.path();
                        if file_name.to_str().unwrap().ends_with(".moz_log") {
                            let h = std::fs::File::open(file_name).unwrap();
                            let bufreader = BufReader::new(h);
                            if let Ok(mut moar_checks) = parse_log(Box::new(bufreader)) {
                                happyblocks.append(&mut moar_checks);
                            }
                        } else {
                            info!("Skipping ineligible file {:?}", file_name);
                        }
                    }
                }
            }
        }
    }

    // now comes the cool analysis, I guess
    println!("happyblocks length: {}", happyblocks.len());
    for c in happyblocks {
        if c.channel_uri.starts_with("data:")
            && !c.channel_uri.starts_with("data:text/css;extension=style;")
            && c.loading_principal == Principal::SystemPrincipal
            && (c.external_content_policy_type == nsContentPolicyType::TYPE_SCRIPT
                || c.external_content_policy_type == nsContentPolicyType::TYPE_STYLESHEET)
        {
            println!("{:?}", c);
        }
    }
    println!("that's all that were interesting.");
    // TODO: parse every -i <file> and add to happyblocks
    /*let input_file_names = matches.opt_strs("i");
    let mut contents = String::new();

    if input_file_names.is_empty() {
        let mut inputhandle: Box<dyn io::Read> = Box::new(io::stdin());
        inputhandle.read_to_string(&mut contents)?;
    } else {
        for inputname in input_file_names {
            let mut file = File::open(inputname)?;
            file.read_to_string(&mut contents)?;
        }
    }*/

    Ok(())
}
