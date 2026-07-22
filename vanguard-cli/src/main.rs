mod cli;

#[tokio::main]
async fn main() -> Result<(), i32> {
    match cli::Cli::exec_cmd().await {
        Ok(_) => {},
        Err(e) => {
            println!("{e}");
            return Err(1)
        }
    };

    Ok(())
}