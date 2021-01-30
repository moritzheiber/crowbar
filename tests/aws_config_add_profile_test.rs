mod common;

use anyhow::Result;
use crowbar::config::aws::{AwsConfig, AWS_CONFIG_FILE, PROFILE_KEY};
use std::env;
use tempfile::NamedTempFile;

#[test]
fn adds_profile_to_file() -> Result<()> {
    let file = NamedTempFile::new()?;
    let location = file.path().to_path_buf();
    let app_profile = common::short_app_profile_a();
    let profile_name = &app_profile.name;

    env::set_var(AWS_CONFIG_FILE, location);

    let config = AwsConfig::new()?;
    config.add_profile(&app_profile)?.write()?;

    let new_config = AwsConfig::new()?;
    let section = format!("profile {}", profile_name);

    assert_eq!(
        Some(format!("sh -c 'crowbar creds {} -p 2> /dev/tty'", profile_name).as_str()),
        new_config.profiles.get_from(Some(section), PROFILE_KEY)
    );

    env::remove_var(AWS_CONFIG_FILE);
    Ok(())
}
