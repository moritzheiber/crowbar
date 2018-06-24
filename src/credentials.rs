use dialoguer::{Input, PasswordInput};
use keyring::Keyring;
use rpassword;
use username;

use failure::Error;

pub fn get_username(org: &str) -> Result<String, Error> {
    let mut input = Input::new(&format!("Username for https://{}.okta.com", org));
    if let Ok(system_user) = username::get_user_name() {
        input.default(&system_user);
    }

    input.interact().map_err(|e| e.into())
}

pub fn get_password(
    organization_name: &str,
    username: &str,
    force_new: bool,
) -> Result<String, Error> {
    if force_new {
        debug!("Force new is set, prompting for password");
        prompt_password(organization_name, username)
    } else {
        match Keyring::new(&format!("oktaws::okta::{}", organization_name), username).get_password()
        {
            Ok(password) => Ok(password),
            Err(e) => {
                debug!(
                    "Retrieving cached password failed, prompting for password because of {:?}",
                    e
                );
                prompt_password(organization_name, username)
            }
        }
    }
}

// We use rpassword here because dialoguer hangs on windows
#[cfg(windows)]
fn prompt_password(org: &str, username: &str) -> Result<String, Error> {
    rpassword::prompt_password_stdout(&format!(
        "Password for https://{}@{}.okta.com: ",
        username, org
    )).map_err(|e| e.into())
}

#[cfg(not(windows))]
fn prompt_password(org: &str, username: &str) -> Result<String, Error> {
    PasswordInput::new(&format!(
        "Password for https://{}@{}.okta.com",
        username, org
    )).interact()
        .map_err(|e| e.into())
}

pub fn set_credentials(org: &str, username: &str, password: &str) {
    info!(
        "Saving Okta credentials for https://{}@{}.okta.com",
        username, org
    );
    let key = format!("oktaws::okta::{}", org);
    let keyring = Keyring::new(&key, username);
    keyring.set_password(password).unwrap();
}
