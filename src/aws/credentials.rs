use dirs;
use failure::Error;
use path_abs::PathFile;
use rusoto_sts::Credentials;
use serde_ini;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::env::var as env_var;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::path::PathBuf;
use std::str;
use try_from::{TryFrom, TryInto};

#[derive(Debug)]
pub struct CredentialsStore {
    file: File,
    credentials: HashMap<String, ProfileCredentials>,
}

impl CredentialsStore {
    pub fn new() -> Result<CredentialsStore, Error> {
        match env_var("AWS_SHARED_CREDENTIALS_FILE") {
            Ok(path) => PathBuf::from(path),
            Err(_) => CredentialsStore::default_profile_location()?,
        }.try_into()
    }

    pub fn set_profile<T: Into<ProfileCredentials>>(
        &mut self,
        name: String,
        creds: T,
    ) -> Result<(), Error> {
        match self.credentials.entry(name) {
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

    pub fn save(self) -> Result<(), Error> {
        info!("Saving AWS credentials");
        serde_ini::ser::to_writer(self.file, &self.credentials).map_err(|e| e.into())
    }

    fn default_profile_location() -> Result<PathBuf, Error> {
        match dirs::home_dir() {
            Some(home_dir) => Ok(home_dir.join(".aws").join("credentials")),
            None => bail!("The environment variable HOME must be set."),
        }
    }
}

impl TryFrom<PathBuf> for CredentialsStore {
    type Err = Error;

    fn try_from(file_path: PathBuf) -> Result<Self, Self::Err> {
        (&file_path).try_into()
    }
}

impl<'a, T: ?Sized + AsRef<Path>> TryFrom<&'a T> for CredentialsStore {
    type Err = Error;

    fn try_from(file_path: &'a T) -> Result<Self, Self::Err> {
        PathFile::create(&file_path)?.try_into()
    }
}

impl TryFrom<PathFile> for CredentialsStore {
    type Err = Error;

    fn try_from(file_path: PathFile) -> Result<Self, Self::Err> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_path)?
            .try_into()
    }
}

impl TryFrom<File> for CredentialsStore {
    type Err = Error;

    fn try_from(mut file: File) -> Result<Self, Self::Err> {
        let credentials = serde_ini::de::from_read(&file)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(CredentialsStore { credentials, file })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum ProfileCredentials {
    Sts {
        #[serde(rename = "aws_access_key_id")]
        access_key_id: String,
        #[serde(rename = "aws_secret_access_key")]
        secret_access_key: String,
        #[serde(rename = "aws_session_token")]
        session_token: String,
    },
    Iam {
        #[serde(rename = "aws_access_key_id")]
        access_key_id: String,
        #[serde(rename = "aws_secret_access_key")]
        secret_access_key: String,
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

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::Builder;
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn parse_sts() {
        let mut tmpfile: File = tempfile::tempfile().unwrap();
        write!(
            tmpfile,
            "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN"
        ).unwrap();
        tmpfile.seek(SeekFrom::Start(0)).unwrap();

        let credentials_store: CredentialsStore = tmpfile.try_into().unwrap();

        let mut expected_credentials = HashMap::new();
        expected_credentials.insert(
            String::from("example"),
            ProfileCredentials::Sts {
                access_key_id: String::from("ACCESS_KEY"),
                secret_access_key: String::from("SECRET_ACCESS_KEY"),
                session_token: String::from("SESSION_TOKEN"),
            },
        );

        assert_eq!(credentials_store.credentials, expected_credentials);
    }

    #[test]
    fn double_entries() {
        let mut tmpfile: File = tempfile::tempfile().unwrap();
        write!(
            tmpfile,
            "
[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN
[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN"
        ).unwrap();
        tmpfile.seek(SeekFrom::Start(0)).unwrap();

        let credentials_store: CredentialsStore = tmpfile.try_into().unwrap();

        let mut expected_credentials = HashMap::new();
        expected_credentials.insert(
            String::from("example"),
            ProfileCredentials::Sts {
                access_key_id: String::from("ACCESS_KEY"),
                secret_access_key: String::from("SECRET_ACCESS_KEY"),
                session_token: String::from("SESSION_TOKEN"),
            },
        );

        assert_eq!(credentials_store.credentials, expected_credentials);
    }

    #[test]
    fn save_sts() {
        let mut named_tempfile = Builder::new()
            .prefix("credentials")
            .rand_bytes(5)
            .tempfile()
            .unwrap();

        write!(
            named_tempfile,
            "
[existing]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN"
        ).unwrap();

        let temp_path = named_tempfile.path();

        let mut credentials_store: CredentialsStore = temp_path.try_into().unwrap();

        credentials_store
            .set_profile(
                String::from("example"),
                ProfileCredentials::Sts {
                    access_key_id: String::from("ACCESS_KEY2"),
                    secret_access_key: String::from("SECRET_ACCESS_KEY2"),
                    session_token: String::from("SESSION_TOKEN2"),
                },
            ).unwrap();

        credentials_store.save().unwrap();

        let mut buf = String::new();
        File::open(temp_path)
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();

        assert_eq!(
            &buf,
            "[example]\r\naws_access_key_id=ACCESS_KEY2\r\naws_secret_access_key=SECRET_ACCESS_KEY2\r\naws_session_token=SESSION_TOKEN2\r\n[existing]\r\naws_access_key_id=ACCESS_KEY\r\naws_secret_access_key=SECRET_ACCESS_KEY\r\n"
        );
    }

    #[test]
    fn parse_iam() {
        let mut tmpfile: File = tempfile::tempfile().unwrap();
        write!(
            tmpfile,
            "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY"
        ).unwrap();
        tmpfile.seek(SeekFrom::Start(0)).unwrap();

        let credentials_store: CredentialsStore = tmpfile.try_into().unwrap();

        let mut expected_credentials = HashMap::new();
        expected_credentials.insert(
            String::from("example"),
            ProfileCredentials::Iam {
                access_key_id: String::from("ACCESS_KEY"),
                secret_access_key: String::from("SECRET_ACCESS_KEY"),
            },
        );

        assert_eq!(credentials_store.credentials, expected_credentials);
    }

}
