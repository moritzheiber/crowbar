extern crate crowbar;

use crowbar::config::app::AppProfile;

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
