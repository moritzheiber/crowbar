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
pub mod credentials;
mod exec;
pub mod exit;
mod providers;
mod saml;
mod utils;

use crate::cli::{CliAction, CliSubAction};
use crate::config::{aws::AwsConfig, CrowbarConfig};
use crate::credentials::aws as CredentialsProvider;
use crate::exec::Executor;
use anyhow::Result;
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
    let executor = Executor::default();

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
        CliAction::Exec { command, profile } => {
            let credentials = CredentialsProvider::fetch_aws_credentials(
                profile,
                crowbar_config,
                force_new_credentials,
            )?;

            let exec = executor.set_command(command).set_credentials(credentials);
            let _exit = exec.run()?.wait();

            Ok(())
        }
        CliAction::Creds { profile, print } => {
            let aws_credentials = CredentialsProvider::fetch_aws_credentials(
                profile,
                crowbar_config,
                force_new_credentials,
            )?;

            if print {
                println!("{}", aws_credentials);
            } else {
                info!("Please run with the -p switch to print the credentials to stdout")
            }

            Ok(())
        }
    }
}
