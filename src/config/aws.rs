use crate::config::app::AppProfile;
use crate::utils;
use anyhow::{anyhow, Context, Result};
use dirs::home_dir;
use ini::Ini;
use std::path::PathBuf;

pub const AWS_CONFIG_FILE: &str = "AWS_CONFIG_FILE";
pub const PROFILE_KEY: &str = "credential_process";

#[derive(Clone)]
pub struct AwsConfig {
    pub profiles: Ini,
    pub location: PathBuf,
}

impl AwsConfig {
    pub fn new() -> Result<AwsConfig> {
        let location = default_config_location()?;
        let profiles = Ini::load_from_file(&location)
            .with_context(|| format!("Unable to read AWS configuration at {:?}", &location))?;

        Ok(AwsConfig { profiles, location })
    }

    pub fn write(self) -> Result<AwsConfig> {
        let location = &self.location;
        self.profiles
            .write_to_file(location)
            .with_context(|| format!("Unable to write AWS configuration at {:?}", location))?;

        Ok(self)
    }

    pub fn add_profile(mut self, profile: &AppProfile) -> Result<AwsConfig> {
        let name = profile.name.clone();
        let key = PROFILE_KEY.to_string();
        let value = format!("sh -c 'crowbar creds {} -p 2> /dev/tty'", &name);

        self.profiles
            .set_to(Some(format!("profile {}", &name)), key, value);

        Ok(self)
    }

    pub fn delete_profile(mut self, profile_name: &str) -> Result<AwsConfig> {
        let profile_name = format!("profile {}", profile_name);
        self.profiles.delete_from(Some(profile_name), PROFILE_KEY);

        Ok(self)
    }
}

fn default_config_location() -> Result<PathBuf> {
    let env = utils::non_empty_env_var(AWS_CONFIG_FILE);
    match env {
        Some(path) => Ok(PathBuf::from(path)),
        None => hardcoded_config_location(),
    }
}

fn hardcoded_config_location() -> Result<PathBuf> {
    match home_dir() {
        Some(mut home_path) => {
            home_path.push(".aws");
            home_path.push("config");
            Ok(home_path)
        }
        None => Err(anyhow!("Failed to determine home directory.")),
    }
}
