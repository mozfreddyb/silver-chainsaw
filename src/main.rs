#[macro_use]
extern crate serde_derive;

extern crate regex;
extern crate serde;
extern crate serde_json;
extern crate url;

use std::env;
use std::fs::File;
use std::io::prelude::*;

mod parsing;

fn print_usage(program: &str) {
    println!("Usage: {} <filename>", program);
}

fn main() -> Result<(), Box<std::error::Error + 'static>>{
 // arg parsing
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();
    if args.len() == 1 {
        print_usage(&program);
        return Ok(());
    }
    let file_name = &args[1];
    //let outfile_name = args[-1];

    let outfile = File::create("parsed.json").unwrap();

    let mut logfile = File::open(file_name).unwrap(); //XXX arg
    let mut contents = String::new();
    logfile.read_to_string(&mut contents)?;
    parsing::parse_log(&contents, outfile);
    Ok(())

}
