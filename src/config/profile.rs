use okta::OktaAppLink;

#[derive(Debug)]
pub struct Profile {
    pub id: String,
    pub application: OktaAppLink,
    pub role: String,
}
