pub mod aws;
pub mod config;

use anyhow::Result;
use std::fmt;

#[derive(Clone)]
pub enum CredentialType {
    Config,
    Aws,
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CredentialType::Config => write!(f, "config"),
            CredentialType::Aws => write!(f, "aws"),
        }
    }
}

pub trait Credential<T, U> {
    fn new(profile: &T) -> Result<U>;
    fn load(profile: &T) -> Result<U>;
    fn write(self, profile: &T) -> Result<U>;
    fn delete(self, profile: &T) -> Result<U>;
}
