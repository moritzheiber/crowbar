extern crate keyring;

mod common;

use anyhow::Result;
use crowbar::credentials::config;
use crowbar::credentials::config::ConfigCredentials;
use crowbar::credentials::Credential;
use keyring::Keyring;

#[test]
fn load_non_existing_config_credentials() -> Result<()> {
    let app_profile = common::short_app_profile_a();
    let creds = ConfigCredentials::load(&app_profile)?;

    assert_eq!(creds, common::empty_config_credentials());

    Ok(())
}

#[test]
fn handles_config_credentials_with_keystore() -> Result<()> {
    let app_profile = common::short_app_profile_b();
    let creds = common::create_config_credentials();

    let creds = creds.write(&app_profile)?;

    let service = config::profile_as_service(&app_profile);
    let value = Keyring::new(&service, &app_profile.username)
        .get_password()
        .ok();

    assert_eq!(creds.password, value);

    let mock_creds = common::create_config_credentials();
    let creds = ConfigCredentials::load(&app_profile)?;

    assert_eq!(creds, mock_creds);

    let _res = creds.delete(&app_profile)?;
    let empty_creds = ConfigCredentials::load(&app_profile)?;

    assert_eq!(ConfigCredentials::default(), empty_creds);

    Ok(())
}
