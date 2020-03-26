extern crate base64;
extern crate clap;
extern crate confy;
extern crate dialoguer;
extern crate keyring;
extern crate kuchiki;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate regex;
extern crate reqwest;
extern crate rusoto_core;
extern crate rusoto_credential;
extern crate rusoto_sts;
#[macro_use]
extern crate serde_derive;
extern crate dirs;
extern crate itertools;
extern crate serde;
extern crate serde_str;
extern crate sxd_document;
extern crate sxd_xpath;
extern crate toml;
extern crate walkdir;
extern crate whoami;

mod aws;
mod cli;
pub mod config;
mod credentials;
pub mod exit;
mod providers;
mod saml;
mod utils;

use crate::cli::{CliAction, CliSubAction};
use crate::config::app::AppProfile;
use crate::config::{aws::AwsConfig, CrowbarConfig};
use crate::credentials::aws::AwsCredentials;
use crate::credentials::config::ConfigCredentials;
use crate::credentials::Credential;
use crate::providers::okta::OktaProvider;
use crate::providers::{Provider, ProviderType};
use anyhow::{anyhow, Result};
use env_logger::{Builder, WriteStyle};
use std::io::Write;

pub fn run() -> Result<()> {
    let cli = cli::config()?;
    let mut logger = Builder::new();
    logger
        .filter(None, Into::into(cli.log_level))
        .write_style(WriteStyle::Never)
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();

    let force_new_credentials = cli.force;
    let cli_action = cli.action;
    let location = cli.location;
    let crowbar_config = CrowbarConfig::with_location(location).read()?;
    let aws_config = AwsConfig::new()?;

    match cli_action {
        CliAction::Profiles { action } => {
            match action {
                CliSubAction::Add { profile } => {
                    crowbar_config.add_profile(&profile)?.write()?;
                    aws_config.add_profile(&profile)?.write()?;
                    println!("Profile {} added successfully!", profile.name)
                }
                CliSubAction::Delete { profile_name } => {
                    crowbar_config.delete_profile(&profile_name)?.write()?;
                    aws_config.delete_profile(&profile_name)?.write()?;
                    println!("Profile {} deleted successfully", profile_name)
                }
                CliSubAction::List {} => crowbar_config.list_profiles()?,
            }
            Ok(())
        }
        CliAction::Creds { profile, print } => {
            let profiles = crowbar_config
                .read()?
                .profiles
                .into_iter()
                .filter(|p| p.clone().is_profile(&profile))
                .collect::<Vec<AppProfile>>();

            if profiles.is_empty() {
                return Err(anyhow!("No profiles available or empty configuration."));
            }

            let profile = match profiles.first() {
                Some(profile) => Ok(profile),
                None => Err(anyhow!("Unable to use parsed profile")),
            }?;

            if force_new_credentials {
                let _creds = ConfigCredentials::load(profile)
                    .map_err(|e| debug!("Couldn't reset credentials: {}", e))
                    .and_then(|creds| creds.delete(profile).map_err(|e| debug!("{}", e)));
            }

            let mut aws_credentials = AwsCredentials::load(&profile).unwrap_or_default();

            if !aws_credentials.valid() || aws_credentials.is_expired() {
                let mut provider = match profile.provider {
                    ProviderType::Okta => OktaProvider::new(profile),
                };
                let session = provider.new_session(profile)?;
                aws_credentials = provider
                    .fetch_aws_credentials(profile, &session)?
                    .write(&profile)?;
            }

            if print {
                println!("{}", aws_credentials);
            } else {
                info!("Please run with the -p switch to print the credentials to stdout")
            }

            Ok(())
        }
    }
}
