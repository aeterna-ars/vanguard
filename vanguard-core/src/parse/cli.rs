pub fn parse_ip_arg(s: &str) -> std::result::Result<Ip, std::io::Error> {
    parse_ip(s.to_string()).map_err(|e| std::io::Error::other(e.to_string()))
}

pub fn parse_eth_arg(s: &str) -> std::result::Result<EtherType, std::io::Error> {
    parse_eth(s.to_string()).map_err(|e| std::io::Error::other(e.to_string()))
}

pub fn parse_proto_arg(s: &str) -> std::result::Result<IpProto, std::io::Error> {
    parse_proto(s.to_string()).map_err(|e| std::io::Error::other(e.to_string()))
}