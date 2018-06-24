pub mod organization;
pub mod profile;

use config::organization::Organization;
use failure::Error;
use std::env::{home_dir, var as env_var};
use std::path::Path;
use std::path::PathBuf;
use try_from::TryInto;
use walkdir::WalkDir;

pub struct Config {
    organizations: Vec<Organization>,
}

impl Config {
    pub fn new() -> Result<Config, Error> {
        let oktaws_home = match env_var("OKTAWS_HOME") {
            Ok(path) => PathBuf::from(path),
            Err(_) => default_profile_location()?,
        };

        Ok(Config {
            organizations: organizations_from_dir(&oktaws_home).collect(),
        })
    }

    pub fn organizations(self) -> impl Iterator<Item = Organization> {
        self.organizations.into_iter()
    }
}

fn organizations_from_dir(dir: &Path) -> impl Iterator<Item = Organization> {
    WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().try_into())
        .filter_map(|r| match r {
            Ok(organization) => Some(organization),
            Err(e) => {
                error!("{:?}", e);
                None
            }
        })
}

fn default_profile_location() -> Result<PathBuf, Error> {
    match home_dir() {
        Some(home_dir) => Ok(home_dir.join(".oktaws")),
        None => bail!("The environment variable HOME must be set."),
    }
}
