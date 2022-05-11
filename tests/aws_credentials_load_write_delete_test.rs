extern crate crowbar;
extern crate keyring;

mod common;

use anyhow::{anyhow, Result};
use crowbar::credentials::aws;
use crowbar::credentials::aws::AwsCredentials;
use crowbar::credentials::Credential;

#[test]
fn load_non_existing_credentials() -> Result<()> {
    let app_profile = common::short_app_profile_a();
    let creds = AwsCredentials::load(&app_profile)?;

    assert_eq!(creds, common::empty_credentials());

    Ok(())
}

#[test]
fn handles_credentials_with_keystore() -> Result<()> {
    let app_profile = common::short_app_profile_b();
    let creds = common::create_credentials();

    let creds = creds.write(&app_profile)?;

    let service = aws::credentials_as_service(&app_profile);
    let value = keyring::Entry::new(&service, "access_key_id")
        .get_password()
        .map_err(|_e| anyhow!("Test failed!"))?;

    assert_eq!(creds.access_key_id.unwrap(), value);

    let mock_creds = common::create_credentials();
    let creds = AwsCredentials::load(&app_profile)?;

    assert_eq!(creds, mock_creds);

    let _res = creds.delete(&app_profile)?;
    let empty_creds = AwsCredentials::load(&app_profile)?;

    assert_eq!(AwsCredentials::default(), empty_creds);

    Ok(())
}
