mod common;

use anyhow::Result;
use crowbar::config::aws::{AwsConfig, AWS_CONFIG_FILE, PROFILE_KEY};
use std::env;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn deletes_profile_key_from_file() -> Result<()> {
    let mut file = NamedTempFile::new()?;
    let location = file.path().to_path_buf();
    let app_profile = common::short_app_profile_a();
    let profile_name = &app_profile.name;

    writeln!(file, "{}", common::long_aws_profile())?;

    env::set_var(AWS_CONFIG_FILE, location);

    let config = AwsConfig::new()?;
    config.delete_profile(profile_name)?.write()?;

    let new_config = AwsConfig::new()?;

    assert_eq!(
        None,
        new_config
            .profiles
            .get_from(Some(format!("profile {}", profile_name)), PROFILE_KEY)
    );
    assert_eq!(1, new_config.profiles.len());

    env::remove_var(AWS_CONFIG_FILE);
    Ok(())
}
