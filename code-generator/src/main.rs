use std::path::Path;
use std::{env, process};

use getopts::Options;

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {program} [options] DICT_FILE...");
    print!("{}", opts.usage(&brief));
    process::exit(0);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt(
        "o",
        "out-dir",
        "[mandatory] a directory to out the generated code",
        "/path/to/out/",
    );
    let matches = opts.parse(&args[1..]).unwrap_or_else(|f| panic!("{}", f));

    if matches.opt_present("h") {
        print_usage(&program, &opts);
    }

    let Some(out_dir_str) = matches.opt_str("o") else {
        panic!("mandatory parameter `-o` (`--out-dir`) is missing")
    };
    let out_dir = Path::new(&out_dir_str);

    let mut dict_file_paths: Vec<&Path> = matches
        .free
        .iter()
        .map(Path::new)
        .inspect(|path| {
            assert!(
                path.exists() && path.is_file(),
                "no such dictionary file => {}",
                path.to_str().unwrap()
            );
        })
        .collect();
    dict_file_paths.sort();

    code_generator::generate(out_dir, &dict_file_paths);
}
