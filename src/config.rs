pub mod app;
pub mod aws;

use crate::config::app::AppProfile;
use crate::config::aws::AwsConfig;
use crate::credentials::aws as AwsCredentialsOperator;
use crate::credentials::config as ConfigCredentialsOperator;
use anyhow::{anyhow, Result};
use clap::crate_name;
use std::default::Default;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CrowbarConfig {
    pub profiles: Vec<AppProfile>,
}

impl Default for CrowbarConfig {
    fn default() -> Self {
        Self { profiles: vec![] }
    }
}

pub fn read_config(location: &Option<String>) -> Result<CrowbarConfig, confy::ConfyError> {
    match location {
        Some(l) => match confy::load_path(l) {
            Ok(config) => Ok(config),
            Err(_e) => {
                error!(
                    "Unable to read configuration data at {}. Using defaults.",
                    l
                );
                Ok(CrowbarConfig::default())
            }
        },
        _ => confy::load(crate_name!()),
    }
}

pub fn add_profile(profile: AppProfile, location: &Option<String>) -> Result<()> {
    let mut crowbar_config = read_config(location)?;
    let aws_config = AwsConfig::new()?;

    // We use our own function here instead of contains() to only
    // filter on the name attribute
    if find_duplicate(&crowbar_config.profiles, &profile) {
        return Err(anyhow!(
            "Profile with the name {} already exists",
            profile.name
        ));
    } else {
        crowbar_config.profiles.push(profile.clone());
        write_config(crowbar_config.profiles, location)?;
    }

    aws_config.add_profile(&profile)?;
    println!("Profile {} added successfully!", profile.name);
    Ok(())
}

pub fn delete_profile(profile_name: String, location: &Option<String>) -> Result<()> {
    let mut profiles = read_config(location)?.profiles;
    let aws_config = AwsConfig::new()?;
    let mut profile = profiles.clone();
    profile.retain(|p| p.name == profile_name);

    if profile.is_empty() {
        return Err(anyhow!("Unable to delete profile: Profile not found"));
    }

    let profile = profile.first().unwrap();
    let mut filter = profiles.clone();
    filter.retain(|p| p.to_string() == profile.to_string());

    if filter.len() < 2 {
        debug!("Removing provider credentials as well");
        ConfigCredentialsOperator::delete(profile)?;
    }

    AwsCredentialsOperator::delete(&profile)?;

    profiles.retain(|p| p.name != profile.name);
    write_config(profiles, location)?;

    aws_config.delete_profile(&profile)?;
    println!("Profile deleted successfully!");

    Ok(())
}

pub fn list_profiles(location: &Option<String>) -> Result<()> {
    let config = read_config(location)?;
    println!("{}", toml::ser::to_string_pretty(&config)?);
    Ok(())
}

fn write_config(profiles: Vec<AppProfile>, location: &Option<String>) -> Result<()> {
    let config = CrowbarConfig { profiles };
    match location {
        Some(l) => confy::store_path(l, config).map_err(|e| e.into()),
        _ => confy::store(crate_name!(), config).map_err(|e| e.into()),
    }
}

fn find_duplicate(vec: &[AppProfile], profile: &AppProfile) -> bool {
    vec.iter().any(|i| i.name == profile.name)
}

#[cfg(test)]

mod test {
    use super::*;
    use crate::providers::ProviderType;
    use claim::{assert_err, assert_ok};
    use tempfile::NamedTempFile;

    #[test]
    fn serializes_valid_config_for_location() {
        let result = read_config(&Some("tests/fixtures/valid_config.toml".to_string()));
        assert_ok!(&result);

        let config = result.unwrap().profiles;
        assert_eq!(config.len(), 1)
    }

    #[test]
    fn serializes_empty_config_for_location_into_empty_vec() -> Result<()> {
        let file = NamedTempFile::new()?;
        let location = file.path().to_str().unwrap().to_owned();
        let result = read_config(&Some(location));
        assert_ok!(&result);

        let config = result.unwrap().profiles;
        assert_eq!(config.len(), 0);

        Ok(())
    }

    #[test]
    fn should_detect_profile_duplicate() {
        let profile_a_vec = vec![profile_a()];
        assert_eq!(true, find_duplicate(&profile_a_vec, &profile_a()));
        assert_eq!(false, find_duplicate(&profile_a_vec, &profile_b()))
    }

    fn profile_a() -> AppProfile {
        AppProfile {
            name: "profile_a".to_owned(),
            username: "username_a".to_owned(),
            provider: ProviderType::Okta,
            url: "https://www.example.com/example/saml".to_owned(),
            role: None,
        }
    }
    fn profile_b() -> AppProfile {
        AppProfile {
            name: "profile_b".to_owned(),
            username: "username_b".to_owned(),
            provider: ProviderType::Okta,
            url: "https://www.example.com/example/saml".to_owned(),
            role: None,
        }
    }

    #[test]
    fn adds_new_profile_to_config() -> Result<()> {
        let file = NamedTempFile::new()?;
        let location = Some(file.path().to_str().unwrap().to_owned());
        let config = CrowbarConfig {
            profiles: vec![profile_a()],
        };
        let _res_ = confy::store_path(location.clone().unwrap(), config)?;

        let profile = profile_b();
        let _res = add_profile(profile, &location)?;

        let config = read_config(&location)?;
        assert_eq!(2, config.profiles.len());
        Ok(())
    }

    #[test]
    fn refuses_to_add_duplicate_profile() -> Result<()> {
        let file = NamedTempFile::new()?;
        let location = Some(file.path().to_str().unwrap().to_owned());
        let config = CrowbarConfig {
            profiles: vec![profile_a()],
        };
        let _res_ = confy::store_path(location.clone().unwrap(), config)?;

        let profile = profile_a();
        let result = add_profile(profile, &location);

        assert_err!(result);
        Ok(())
    }

    #[test]
    fn removes_profile_from_configuration() -> Result<()> {
        let file = NamedTempFile::new()?;
        let location = Some(file.path().to_str().unwrap().to_owned());
        let config = CrowbarConfig {
            profiles: vec![profile_a(), profile_b()],
        };
        let _res_ = confy::store_path(location.clone().unwrap(), config)?;

        let config = read_config(&location)?;
        assert_eq!(2, config.profiles.len());

        let profile = profile_a();
        delete_profile(profile.name, &location)?;

        let config = read_config(&location)?;
        assert_eq!(1, config.profiles.len());
        Ok(())
    }

    #[test]
    fn error_on_profile_not_exist() -> Result<()> {
        let file = NamedTempFile::new()?;
        let location = file.path().to_str().unwrap().to_owned();
        let config = CrowbarConfig {
            profiles: vec![profile_b()],
        };
        let _res_ = confy::store_path(&location, config)?;
        let profile = profile_a();

        assert_err!(delete_profile(profile.name, &Some(location)));

        Ok(())
    }
}
