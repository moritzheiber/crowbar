extern crate crowbar;
extern crate keyring;

use crowbar::config::app::AppProfile;
use crowbar::credentials::aws;
use crowbar::credentials::aws::AwsCredentials;
use keyring::Keyring;
use std::collections::HashMap;

#[allow(dead_code)]
pub fn short_app_profile_a() -> AppProfile {
    toml::from_str(
        r#"
        name = "profile_a"
        provider = "okta"
        url = "https://example.com/example/url"
        username = "username"
    "#
        .trim_start(),
    )
    .unwrap()
}

#[allow(dead_code)]
pub fn short_app_profile_b() -> AppProfile {
    toml::from_str(
        r#"
        name = "profile_b"
        provider = "okta"
        url = "https://example.com/example/url"
        username = "username"
    "#
        .trim_start(),
    )
    .unwrap()
}

#[allow(dead_code)]
pub fn long_aws_profile() -> String {
    r#"
    [profile profile]
    region=eu-central-1
    credential_process=sh -c 'crowbar creds profile -p 2> /dev/tty'
    "#
    .trim_start()
    .to_string()
}

#[allow(dead_code)]
pub fn short_aws_profile() -> String {
    r#"
    [profile profile]
    credential_process=sh -c 'crowbar creds profile -p 2> /dev/tty'
    "#
    .trim_start()
    .to_string()
}

#[allow(dead_code)]
pub fn create_credentials() -> AwsCredentials {
    AwsCredentials {
        version: 1,
        access_key_id: Some("some_key".to_string()),
        secret_access_key: Some("some_secret".to_string()),
        session_token: Some("some_token".to_string()),
        expiration: Some("2038-01-01T10:10:10Z".to_string()),
    }
}

#[allow(dead_code)]
pub fn empty_credentials() -> AwsCredentials {
    AwsCredentials {
        version: 1,
        access_key_id: None,
        secret_access_key: None,
        session_token: None,
        expiration: None,
    }
}

#[allow(dead_code)]
pub fn clean_keystore(profile: &AppProfile, creds: AwsCredentials) {
    let credential_map: HashMap<String, Option<String>> = creds.into();
    let service = aws::credentials_as_service(profile);

    for key in credential_map.keys() {
        Keyring::new(&service, key).delete_password().unwrap()
    }
}
