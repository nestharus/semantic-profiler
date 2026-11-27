fn main() {
    match semantic_profiler::cli::run(std::env::args()) {
        Ok(code) => std::process::exit(code),
        Err(msg) => {
            eprintln!("error: {msg}");
            std::process::exit(1);
        }
    }
}
