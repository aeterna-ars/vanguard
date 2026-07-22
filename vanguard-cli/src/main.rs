mod cli;

fn main() -> Result<(), i32> {
    match cli::Cli::exec_cmd() {
        Ok(_) => {},
        Err(e) => return Err(1),
    };

    Ok(())
}