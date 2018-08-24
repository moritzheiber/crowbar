#![warn(unused)]

extern crate base64;
extern crate dialoguer;
#[macro_use]
extern crate failure;
extern crate keyring;
extern crate kuchiki;
#[macro_use]
extern crate log;
extern crate path_abs;
extern crate pretty_env_logger;
extern crate regex;
extern crate reqwest;
extern crate rpassword;
extern crate rusoto_core;
extern crate rusoto_credential;
extern crate rusoto_sts;
extern crate stderrlog;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_ini;
extern crate serde_str;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate flexi_logger;
extern crate glob;
extern crate rayon;
extern crate serde_json;
extern crate sxd_document;
extern crate sxd_xpath;
extern crate toml;
extern crate try_from;
extern crate username;
extern crate walkdir;

mod aws;
mod config;
mod credentials;
mod okta;
mod saml;

use aws::credentials::CredentialsStore;
use config::organization::Organization;
use config::profile::Profile;
use config::Config;
use okta::auth::LoginRequest;
use rayon::prelude::*;
use std::env;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

use failure::Error;
use flexi_logger::Logger;
use glob::Pattern;

#[derive(Clone, StructOpt, Debug)]
pub struct Opt {
    /// Profile to update
    #[structopt(default_value = "*", parse(try_from_str))]
    pub profiles: Pattern,

    /// Okta organization to use
    #[structopt(
        short = "o",
        long = "organizations",
        default_value = "*",
        parse(try_from_str)
    )]
    pub organizations: Pattern,

    /// Forces new credentials
    #[structopt(short = "f", long = "force-new")]
    pub force_new: bool,

    /// Sets the level of verbosity
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbosity: usize,

    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    pub quiet: bool,

    /// Run in a synchronous manner (no parallel)
    #[structopt(short = "s", long = "sync")]
    pub synchronous: bool,
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();

    /*stderrlog::new()
        .module(module_path!())
        .quiet(opt.quiet)
        .verbosity(opt.verbosity + 2)
        .init()?;*/

    /*Logger::with_env_or_str("oktaws=info")
        .format(flexi_logger::with_thread)
        .start()?;*/

    let log_level = match opt.verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    env::set_var("RUST_LOG", format!("{}={}", module_path!(), log_level));
    pretty_env_logger::init();

    let config = Config::new()?;

    let credentials_store = Arc::new(Mutex::new(CredentialsStore::new()?));

    let organizations = config
        .organizations()
        .filter(|o| opt.organizations.matches(&o.name))
        .collect::<Vec<Organization>>();

    if organizations.is_empty() {
        bail!("No organizations found called {}", opt.organizations);
    } else {
        for mut organization in organizations {
            info!("Evaluating profiles in {}", organization.name);

            let mut okta_client = organization.okta_client();
            let (username, password) = organization.credentials(opt.force_new)?;

            let session_token = okta_client.get_session_token(&LoginRequest::from_credentials(
                username.clone(),
                password.clone(),
            ))?;

            let session_id = okta_client.get_session_id(&session_token)?;
            okta_client.set_session_id(session_id.clone());

            let profiles = organization
                .profiles(&okta_client)?
                .filter(|p| opt.profiles.matches(&p.id))
                .collect::<Vec<Profile>>();

            if profiles.is_empty() {
                warn!(
                    "No profiles found matching {} in {}",
                    opt.profiles, organization.name
                );
            } else {
                let credentials_generator = |profile: &Profile| -> Result<(), Error> {
                    info!("Generating tokens for {}", &profile.id);

                    let mut okta_client = organization.okta_client();
                    okta_client.set_session_id(session_id.clone());

                    let saml =
                        match okta_client.get_saml_response(profile.application.link_url.clone()) {
                            Ok(saml) => saml,
                            Err(e) => bail!(
                                "Error getting SAML response for profile {} ({})",
                                profile.id,
                                e
                            ),
                        };

                    trace!("SAML assertion: {:?}", saml);

                    let roles = saml.roles;

                    debug!("SAML Roles: {:?}", &roles);

                    match roles
                        .into_iter()
                        .find(|r| r.role_name().map(|r| r == profile.role).unwrap_or(false))
                    {
                        Some(role) => {
                            debug!("Found role: {} in {}", role.role_arn, &profile.id);

                            let raw_saml = saml.raw;

                            let assumption_response = match aws::role::assume_role(
                                role,
                                raw_saml.clone(),
                            ) {
                                Ok(res) => res,
                                Err(e) => {
                                    bail!("Error assuming role for profile {} ({})", profile.id, e);
                                }
                            };

                            if let Some(credentials) = assumption_response.credentials {
                                debug!("Credentials: {:?}", credentials);

                                credentials_store
                                    .lock()
                                    .unwrap()
                                    .set_profile(profile.id.clone(), credentials)
                            } else {
                                bail!("Error fetching credentials from assumed AWS role")
                            }
                        }
                        None => bail!(
                            "No matching role ({}) found for profile {}",
                            profile.role,
                            &profile.id
                        ),
                    }
                };

                if opt.synchronous {
                    profiles.iter().try_for_each(credentials_generator)?
                } else {
                    profiles.par_iter().try_for_each(credentials_generator)?
                }
            }
        }

        Arc::try_unwrap(credentials_store)
            .unwrap()
            .into_inner()
            .unwrap()
            .save()
    }
}
