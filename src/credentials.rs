pub mod aws;
pub mod config;

#[derive(PartialEq, Debug)]
pub enum CredentialState {
    Valid,
    Expired,
}

pub trait State {
    fn state(&self) -> CredentialState;
}
