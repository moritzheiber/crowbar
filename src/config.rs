pub mod app;
pub mod aws;

use crate::config::app::AppProfile;
use anyhow::{anyhow, Result};
use clap::crate_name;
use std::default::Default;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CrowbarConfig {
    pub profiles: Vec<AppProfile>,
    pub location: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct AppProfiles {
    profiles: Vec<AppProfile>,
}

impl Default for CrowbarConfig {
    fn default() -> Self {
        Self {
            profiles: vec![],
            location: None,
        }
    }
}

impl Default for AppProfiles {
    fn default() -> Self {
        Self { profiles: vec![] }
    }
}

impl CrowbarConfig {
    pub fn new() -> CrowbarConfig {
        CrowbarConfig::default()
    }

    pub fn with_location(location: Option<String>) -> CrowbarConfig {
        let mut config = CrowbarConfig::new();
        config.location = location;
        config
    }

    pub fn read(mut self) -> Result<CrowbarConfig> {
        let app_profiles: AppProfiles = match &self.location {
            Some(l) => confy::load_path(l)?,
            _ => confy::load(crate_name!())?,
        };
        self.profiles = app_profiles.profiles;

        Ok(self)
    }

    pub fn add_profile(mut self, profile: &AppProfile) -> Result<CrowbarConfig> {
        // We use our own function here instead of contains() to only
        // filter on the name attribute
        if find_duplicate(&self.profiles, profile) {
            return Err(anyhow!(
                "Profile with the name {} already exists",
                profile.name
            ));
        } else {
            self.profiles.push(profile.clone());
        }

        Ok(self)
    }

    pub fn delete_profile(mut self, profile_name: &str) -> Result<CrowbarConfig> {
        let mut profile = self.profiles.clone();
        profile.retain(|p| p.name == profile_name);

        if profile.is_empty() {
            return Err(anyhow!("Unable to delete profile: Profile not found"));
        }

        let profile = profile.first().unwrap();
        let mut filter = self.profiles.clone();
        filter.retain(|p| p.to_string() == profile.to_string());

        self.profiles.retain(|p| p.name != profile.name);

        Ok(self)
    }

    pub fn list_profiles(&self) -> Result<()> {
        println!("{}", toml::ser::to_string_pretty(&self)?);
        Ok(())
    }

    pub fn write(self) -> Result<()> {
        let app_profiles = AppProfiles {
            profiles: self.profiles,
        };

        match self.location {
            Some(l) => confy::store_path(l, app_profiles).map_err(|e| e.into()),
            _ => confy::store(crate_name!(), app_profiles).map_err(|e| e.into()),
        }
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

    #[test]
    fn serializes_valid_config_for_location() -> Result<()> {
        let crowbar_config =
            CrowbarConfig::with_location(Some("tests/fixtures/valid_config.toml".to_string()));
        let result = crowbar_config.read();
        assert_ok!(&result);

        let config = result?.profiles;
        assert_eq!(config.len(), 1);

        Ok(())
    }

    #[test]
    fn serializes_empty_config_for_location_into_empty_vec() -> Result<()> {
        let crowbar_config = CrowbarConfig::with_location(Some("/tmp/some/location".to_string()));
        let result = crowbar_config.read();
        assert_ok!(&result);

        let config = result?.profiles;
        assert_eq!(config.len(), 0);

        Ok(())
    }

    #[test]
    fn should_detect_profile_duplicate() {
        let profile_a_vec = vec![profile_a()];
        assert_eq!(true, find_duplicate(&profile_a_vec, &profile_a()));
        assert_eq!(false, find_duplicate(&profile_a_vec, &profile_b()))
    }

    #[test]
    fn adds_new_profile_to_config() -> Result<()> {
        let config = CrowbarConfig::new();

        assert_eq!(0, config.profiles.len());

        let new_config = config.add_profile(&profile_a())?;

        assert_eq!(1, new_config.profiles.len());
        Ok(())
    }

    #[test]
    fn refuses_to_add_duplicate_profile() -> Result<()> {
        let config = CrowbarConfig {
            profiles: vec![profile_a()],
            location: None,
        };

        let result = config.add_profile(&profile_a());

        assert_err!(result);
        Ok(())
    }

    #[test]
    fn removes_profile_from_configuration() -> Result<()> {
        let config = CrowbarConfig {
            profiles: vec![profile_a(), profile_b()],
            location: None,
        };

        assert_eq!(2, config.profiles.len());

        let profile = profile_a();
        let new_config = config.delete_profile(&profile.name)?;

        assert_eq!(1, new_config.profiles.len());
        Ok(())
    }

    #[test]
    fn error_on_profile_not_exist() -> Result<()> {
        let config = CrowbarConfig {
            profiles: vec![profile_b()],
            location: None,
        };

        let profile = profile_a();
        assert_err!(config.delete_profile(&profile.name));

        Ok(())
    }

    // Test helper functions
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
}
