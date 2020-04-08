use crate::aws::role::Role as AwsRole;
use crate::config::app::AppProfile;

use anyhow::{anyhow, Result};
use dialoguer::{theme::SimpleTheme, Select};
use dialoguer::{Input, PasswordInput};
use log::LevelFilter as LogLevelFilter;
use std::collections::HashSet;
use std::env::var;

#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq, Hash)]
pub enum LevelFilter {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Into<LogLevelFilter> for LevelFilter {
    fn into(self) -> LogLevelFilter {
        match self {
            LevelFilter::Debug => LogLevelFilter::Debug,
            LevelFilter::Warn => LogLevelFilter::Warn,
            LevelFilter::Error => LogLevelFilter::Error,
            LevelFilter::Trace => LogLevelFilter::Trace,
            LevelFilter::Info => LogLevelFilter::Info,
            LevelFilter::Off => LogLevelFilter::Off,
        }
    }
}

pub fn non_empty_env_var(name: &str) -> Option<String> {
    match var(name) {
        Ok(value) => {
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        }
        Err(_) => None,
    }
}

pub fn prompt_password(profile: &AppProfile) -> Result<String> {
    PasswordInput::new()
        .with_prompt(&format!(
            "Password for {} at {}",
            &profile.username,
            profile.clone().base_url()?.host().unwrap()
        ))
        .interact()
        .map_err(|e| e.into())
}

pub fn prompt_mfa() -> Result<String> {
    let mut input = Input::new();
    let input = input.with_prompt("MFA response");

    match input.interact() {
        Ok(mfa) => Ok(mfa),
        Err(e) => Err(anyhow!("Failed to get MFA input: {}", e)),
    }
}

pub fn select_role(roles: HashSet<AwsRole>) -> Result<AwsRole> {
    let selection = match roles.clone() {
        r if r.len() < 2 => 0,
        r => Select::with_theme(&SimpleTheme)
            .with_prompt("Select the role to assume:")
            .default(0)
            .items(
                &r.iter()
                    .map(|r| r.clone().role_arn)
                    .collect::<Vec<String>>(),
            )
            .interact()
            .unwrap(),
    };

    Ok(roles.iter().collect::<Vec<&AwsRole>>()[selection].to_owned())
}
