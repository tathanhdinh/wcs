use lief_sys;

use structopt::{self, StructOpt};
use std::path;

#[derive(StructOpt)]
#[structopt(name = "wcs", about = "Security checker for PE")]
struct Args {
    #[structopt(name = "PE file", parse(from_os_str))]
    input: path::PathBuf,
}

fn main() {
    // println!("Hello, world!");
    let args = Args::from_args();

    let mut pe = {
        let pe = unsafe { lief_sys::pe_parse(args.input.to_string_lossy().as_ptr() as *const i8) };
        unsafe { *pe }
    };

    
}
