#[derive(Debug, erret_macro::Error)]
pub enum VanguardError {
    #[error("Cli error: {}")]
    Cli(&'static str),

    #[error("eBPF error: {}")]
    EbpfMap(String),

    #[error("Ebpf error: {}")]
    Ebpf(&'static str),

    #[error("IO error: {}")]
    Io(&'static str),

    #[error("Serde error: {}")]
    Grpc(&'static str),

    #[error("Daemon error: {}")]
    Daemon(String)
}