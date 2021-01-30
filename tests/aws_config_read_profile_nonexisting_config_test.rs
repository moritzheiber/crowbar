mod common;

use anyhow::Result;
use crowbar::config::aws::{AwsConfig, AWS_CONFIG_FILE};
use std::env;
use tempfile::tempdir;

#[test]
fn adds_profile_to_file() -> Result<()> {
    let dir = tempdir()?;
    let location = dir.path().join(".aws/config");

    env::set_var(AWS_CONFIG_FILE, &location);

    let config = AwsConfig::new()?;

    assert_eq!(location, config.location);

    env::remove_var(AWS_CONFIG_FILE);
    Ok(())
}
