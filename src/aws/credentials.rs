use failure::Error;
use path_abs::PathFile;
use serde_ini;
use rusoto_sts::Credentials;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::env;
use std::str;

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialsStore(HashMap<String, ProfileCredentials>);

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ProfileCredentials {
    Sts {
        #[serde(rename = "aws_access_key_id")] access_key_id: String,
        #[serde(rename = "aws_secret_access_key")] secret_access_key: String,
        #[serde(rename = "aws_session_token")] session_token: String,
    },
    Iam {
        #[serde(rename = "aws_access_key_id")] access_key_id: String,
        #[serde(rename = "aws_secret_access_key")] secret_access_key: String,
    },
}

impl From<Credentials> for ProfileCredentials {
    fn from(creds: Credentials) -> Self {
        ProfileCredentials::Sts {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
        }
    }
}

impl CredentialsStore {
    pub fn new() -> Result<CredentialsStore, Error> {
        Ok(CredentialsStore(serde_ini::de::from_str(
            &CredentialsStore::path()?.read_string()?,
        )?))
    }

    pub fn set_profile<T: Into<ProfileCredentials>>(
        &mut self,
        name: String,
        creds: T,
    ) -> Result<(), Error> {
        match self.0.entry(name) {
            Entry::Occupied(mut entry) => match *entry.get() {
                ProfileCredentials::Sts { .. } => {
                    entry.insert(creds.into());
                }
                ProfileCredentials::Iam { .. } => {
                    bail!(
                        "Profile '{}' does not contain STS credentials. Ignoring",
                        entry.key()
                    );
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(creds.into());
            }
        }
        Ok(())
    }

    pub fn save(&self) -> Result<(), Error> {
        info!("Saving AWS credentials");
        CredentialsStore::path()?
            .write_str(&serde_ini::ser::to_string(self)?)
            .map_err(|e| e.into())
    }

    fn path() -> Result<PathFile, Error> {
        match env::home_dir() {
            Some(home_dir) => {
                PathFile::create(home_dir.join(".aws/credentials")).map_err(|e| e.into())
            }
            None => bail!("No home dir detected"),
        }
    }
}
