#[macro_use]
extern crate serde_derive;

extern crate regex;
extern crate serde;
extern crate serde_json;
extern crate url;


use std::fs::File;
use std::io::prelude::*;

mod parsing;

fn main() {
    let mut outfile = File::create("parsed.out").unwrap();

    let mut logfile = File::open("csmlog.txt").unwrap(); //XXX arg
    let mut contents = String::new();
    logfile.read_to_string(&mut contents);
    parsing::parse_log(&contents, outfile);
}
