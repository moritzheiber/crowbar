use reqwest::Url;
use serde_str;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Links {
    Single(Link),
    Multi(Vec<Link>),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    name: Option<String>,
    #[serde(with = "serde_str")]
    pub href: Url,
    hints: Hint,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    allow: Vec<String>,
}
