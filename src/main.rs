#[macro_use]
extern crate serde_derive;

extern crate getopts;
extern crate regex;
extern crate serde;
extern crate serde_json;
extern crate url;


use getopts::Options;
use std::env;
use std::fs::File;
use std::io;
//use std::io::prelude::*;
use std::io::{Read};

mod parsing;

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() -> io::Result<()> {
    // arg parsing
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("v", "verbose", "give more verbose output");
    opts.optflag("h", "help", "print usage info");
    opts.optopt("o", "output", "print to this file (default is stdout)", "OUTFILE");
    opts.optmulti("i", "input", "read from these files", "INFILE");
    let mut verbosity_lvl = 0;
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m },
        Err(e) => { panic!(e.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, &opts);
        return Ok(());
    }
    if matches.opt_present("v") {
        verbosity_lvl = 1;
    }
    let input_file_names = matches.opt_strs("i");
    let mut contents = String::new();


    if input_file_names.is_empty() {
        let mut inputhandle: Box<io::Read>= Box::new(io::stdin());
        inputhandle.read_to_string(&mut contents)?;
    } else {
        for inputname in input_file_names {
            let mut file = File::open(inputname)?;
            file.read_to_string(&mut contents)?;
        }
    }

    if contents.is_empty() {
        eprintln!("Warning: Empty input file!");
    }
    let output_file_name = matches.opt_str("o");
    let outhandle: Box<io::Write> = match output_file_name {
        Some(f) => Box::new(File::create(f)?),
        None => Box::new(io::stdout()),
    };

    parsing::parse_log(&contents, verbosity_lvl, outhandle)
}
