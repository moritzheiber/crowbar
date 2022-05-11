use crate::aws::role::Role as AwsRole;
use crate::config::app::AppProfile;

use anyhow::{Context, Result};
use dialoguer::{theme::SimpleTheme, Select};
use dialoguer::{Input, PasswordInput};
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

impl From<LevelFilter> for log::LevelFilter {
    fn from(level_filter: LevelFilter) -> log::LevelFilter {
        match level_filter {
            LevelFilter::Debug => log::LevelFilter::Debug,
            LevelFilter::Warn => log::LevelFilter::Warn,
            LevelFilter::Error => log::LevelFilter::Error,
            LevelFilter::Trace => log::LevelFilter::Trace,
            LevelFilter::Info => log::LevelFilter::Info,
            LevelFilter::Off => log::LevelFilter::Off,
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
    Input::new()
        .with_prompt("Enter MFA code")
        .interact()
        .with_context(|| "Failed to get MFA input")
}

pub fn select_role(roles: HashSet<AwsRole>, role: Option<String>) -> Result<AwsRole> {
    let selection = match role {
        None => match roles.clone() {
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
        },
        Some(role) => match roles.iter().position(|r| r.role_arn == role) {
            None => match roles.clone() {
                r if r.len() < 2 => 0,
                r => Select::with_theme(&SimpleTheme)
                    .with_prompt(&format!(
                        "Role {} not found; select the role to assume:",
                        role
                    ))
                    .default(0)
                    .items(
                        &r.iter()
                            .map(|r| r.clone().role_arn)
                            .collect::<Vec<String>>(),
                    )
                    .interact()
                    .unwrap(),
            },
            Some(selection) => selection,
        },
    };

    Ok(roles.iter().collect::<Vec<&AwsRole>>()[selection].to_owned())
}
