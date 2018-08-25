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
#[macro_use]
extern crate serde_derive;
extern crate dirs;
extern crate glob;
extern crate rayon;
extern crate serde;
extern crate serde_ini;
extern crate serde_str;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate itertools;
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

use failure::Error;
use glob::Pattern;
use rayon::prelude::*;
use std::collections::HashSet;
use std::env;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

use aws::credentials::CredentialsStore;
use aws::role::Role;
use config::organization::Profile;
use config::Config;
use okta::auth::LoginRequest;
use okta::client::Client as OktaClient;

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

    /// Run in an asynchronous manner (parallel)
    #[structopt(short = "a", long = "async")]
    pub asynchronous: bool,
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();

    let log_level = match opt.verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env::set_var("RUST_LOG", format!("{}={}", module_path!(), log_level));

    pretty_env_logger::init();

    let config = Config::new()?;

    let credentials_store = Arc::new(Mutex::new(CredentialsStore::new()?));

    let mut organizations = config
        .organizations()
        .filter(|o| opt.organizations.matches(&o.okta_organization.name))
        .peekable();

    if organizations.peek().is_none() {
        bail!("No organizations found called {}", opt.organizations);
    }

    for mut organization in organizations {
        info!(
            "Evaluating profiles in {}",
            organization.okta_organization.name
        );

        let mut okta_client = OktaClient::new(organization.okta_organization.clone());
        let username = organization.username.to_owned();
        let password =
            credentials::get_password(&organization.okta_organization, &username, opt.force_new)?;

        let session_token = okta_client.get_session_token(&LoginRequest::from_credentials(
            username.clone(),
            password.clone(),
        ))?;

        let session_id = okta_client.new_session(session_token, HashSet::new())?.id;
        okta_client.set_session_id(session_id.clone());

        let profiles = organization
            .profiles(&okta_client)?
            .filter(|p| opt.profiles.matches(&p.id))
            .collect::<Vec<Profile>>();

        if profiles.is_empty() {
            warn!(
                "No profiles found matching {} in {}",
                opt.profiles, organization.okta_organization.name
            );
        } else {
            let credentials_generator = |profile: &Profile| -> Result<(), Error> {
                info!(
                    "Requesting tokens for {}/{}",
                    &organization.okta_organization.name, &profile.id
                );

                let mut okta_client = OktaClient::new(organization.okta_organization.clone());
                okta_client.set_session_id(session_id.clone());

                let saml = match okta_client.get_saml_response(profile.application.link_url.clone())
                {
                    Ok(saml) => saml,
                    Err(e) => bail!(
                        "Error getting SAML response for profile {} ({})",
                        profile.id,
                        e
                    ),
                };

                trace!("SAML response: {:?}", saml);

                let roles = saml.roles;

                debug!("SAML Roles: {:?}", &roles);

                let role: Role = match roles
                    .into_iter()
                    .find(|r| r.role_name().map(|r| r == profile.role).unwrap_or(false))
                {
                    Some(role) => role,
                    None => bail!(
                        "No matching role ({}) found for profile {}",
                        profile.role,
                        &profile.id
                    ),
                };

                trace!("Found role: {} for profile {}", role.role_arn, &profile.id);

                let assumption_response = match aws::role::assume_role(role, saml.raw) {
                    Ok(res) => res,
                    Err(e) => bail!("Error assuming role for profile {} ({})", profile.id, e),
                };

                let credentials = match assumption_response.credentials {
                    Some(credentials) => credentials,
                    None => bail!("Error fetching credentials from assumed AWS role"),
                };

                trace!("Credentials: {:?}", credentials);

                credentials_store
                    .lock()
                    .unwrap()
                    .set_profile(profile.id.clone(), credentials)
            };

            if opt.asynchronous {
                profiles.par_iter().try_for_each(credentials_generator)?;
            } else {
                profiles.iter().try_for_each(credentials_generator)?;
            }
        }

        credentials::save_credentials(&organization.okta_organization, &username, &password)?;
    }

    Arc::try_unwrap(credentials_store)
        .map_err(|_| format_err!("Failed to un-reference count the credentials store"))?
        .into_inner()
        .map_err(|_| format_err!("Failed to un-mutex the credentials store"))?
        .save()
}
