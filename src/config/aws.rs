use crate::config::app::AppProfile;
use crate::utils;
use anyhow::{anyhow, Result};
use dirs::home_dir;
use ini::Ini;
use std::path::PathBuf;

pub const AWS_CONFIG_FILE: &str = "AWS_CONFIG_FILE";
pub const PROFILE_KEY: &str = "credential_process";

#[derive(Clone)]
pub struct AwsConfig {
    pub profiles: Ini,
}

impl AwsConfig {
    pub fn new() -> Result<AwsConfig> {
        Ok(AwsConfig {
            profiles: AwsConfig::read_configuration()?,
        })
    }

    fn read_configuration() -> Result<Ini> {
        let location = AwsConfig::default_config_location()?;
        Ini::load_from_file(location).map_err(|e| e.into())
    }

    fn write_configuration(self) -> Result<()> {
        let location = AwsConfig::default_config_location()?;
        self.profiles.write_to_file(location).map_err(|e| e.into())
    }

    fn default_config_location() -> Result<PathBuf> {
        let env = utils::non_empty_env_var(AWS_CONFIG_FILE);
        match env {
            Some(path) => Ok(PathBuf::from(path)),
            None => AwsConfig::hardcoded_config_location(),
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

    pub fn add_profile(mut self, profile: &AppProfile) -> Result<()> {
        let name = profile.name.clone();
        let key = PROFILE_KEY.to_string();
        let value = format!("sh -c 'crowbar creds {} -p 2> /dev/tty'", &name);

        self.profiles
            .set_to(Some(format!("profile {}", &name)), key, value);
        self.write_configuration()?;

        Ok(())
    }

    pub fn delete_profile(mut self, profile: &AppProfile) -> Result<()> {
        let name = profile.name.clone();
        let profile_name = format!("profile {}", &name);
        self.profiles.delete_from(Some(profile_name), PROFILE_KEY);

        self.write_configuration()?;

        Ok(())
    }
}
