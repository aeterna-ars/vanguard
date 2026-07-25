use serde::{Deserialize, Deserializer};

pub fn deserialize_ip<'de, D>(deserializer: D) -> Result<Ip, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(parse_ip(s).map_err(|e| SerdeDeError::custom(format!("{e}")))?)
}

pub fn deserialize_ip_list<'de, D>(deserializer: D) -> Result<Vec<Ip>, D::Error>
where
    D: Deserializer<'de>,
{
    let list = Vec::<String>::deserialize(deserializer)?;

    list.iter()
        .map(|s| parse_ip(s.to_string())
            .map_err(|e| SerdeDeError::custom(format!("{e}"))))
        .collect()
}

pub fn deserialize_eth<'de, D>(deserializer: D) -> Result<EtherType, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(parse_eth(s).map_err(|e| SerdeDeError::custom(format!("{e}")))?)
}

pub fn deserialize_proto<'de, D>(deserializer: D) -> Result<IpProto, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(parse_proto(s).map_err(|e| SerdeDeError::custom(format!("{e}")))?)
}

pub fn deserialize_action<'de, D>(deserializer: D) -> Result<RuleAction, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(parse_action(s).map_err(|e| SerdeDeError::custom(format!("{e}")))?)
}