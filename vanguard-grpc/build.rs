use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("src/grpc");
    std::fs::create_dir_all(out_dir)?;

    println!("cargo:rerun-if-changed=vanguard_api.proto");

    tonic_prost_build::configure()
        .out_dir(out_dir)
        .compile_protos(&["vanguard_api.proto"], &["."])?;

    Ok(())
}