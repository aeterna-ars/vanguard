#[derive(Debug, erret_macro::Error)]
pub enum VanguardError {
    #[error("eBPF map error: {}")]
    EbpfMapError(String),

    #[error("IO error: {}")]
    IoError(&'static str)
}