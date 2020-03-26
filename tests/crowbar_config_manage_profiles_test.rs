extern crate crowbar;

mod common;

use anyhow::Result;
use crowbar::config::CrowbarConfig;
use tempfile::NamedTempFile;

#[test]
fn adds_profile_to_file() -> Result<()> {
    let file = NamedTempFile::new()?;
    let location = file.path().to_str().unwrap().to_owned();
    let app_profile = common::short_app_profile_a();

    let config = CrowbarConfig::with_location(Some(location.clone()));
    config.add_profile(&app_profile)?.write()?;

    let new_config = CrowbarConfig::with_location(Some(location)).read()?;

    assert_eq!(1, new_config.profiles.len());

    Ok(())
}

#[test]
fn removes_profile_from_file() -> Result<()> {
    let file = NamedTempFile::new()?;
    let location = file.path().to_str().unwrap().to_owned();
    let profile_a = common::short_app_profile_a();
    let profile_b = common::short_app_profile_b();

    let config = CrowbarConfig::with_location(Some(location.clone()));
    let config = config.add_profile(&profile_a)?;
    let config = config.add_profile(&profile_b)?;
    config.write()?;

    let new_config = CrowbarConfig::with_location(Some(location.clone())).read()?;
    let new_config = new_config.delete_profile(&profile_a.name)?;
    new_config.write()?;

    let assert_config = CrowbarConfig::with_location(Some(location)).read()?;

    let profiles = assert_config.profiles;

    assert_eq!(1, profiles.len());
    assert_eq!(profiles[0].name, profile_b.name);
    assert_eq!(profiles[0].url, profile_b.url);
    assert_eq!(profiles[0].username, profile_b.username);

    Ok(())
}
