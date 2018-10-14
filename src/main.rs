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
#[cfg(windows)]
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
mod okta;
mod saml;

use aws::credentials::CredentialsStore;
use aws::role::Role;
use config::credentials;
use config::organization::Organization;
use config::organization::Profile;
use config::Config;
use failure::Error;
use glob::Pattern;
use okta::auth::LoginRequest;
use okta::client::Client as OktaClient;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use rusoto_sts::Credentials;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

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
            .profiles
            .clone()
            .into_iter()
            .filter(|p| opt.profiles.matches(&p.name))
            .collect::<Vec<Profile>>();

        if profiles.is_empty() {
            warn!(
                "No profiles found matching {} in {}",
                opt.profiles, organization.okta_organization.name
            );
            continue;
        }

        let credentials_folder = |mut acc: HashMap<String, Credentials>,
                                  profile: &Profile|
         -> Result<HashMap<String, Credentials>, Error> {
            let credentials = fetch_credentials(&okta_client, &organization, &profile)?;
            acc.insert(profile.name.clone(), credentials);

            Ok(acc)
        };

        let org_credentials = if opt.asynchronous {
            profiles
                .par_iter()
                .try_fold(|| HashMap::new(), credentials_folder)
                .try_reduce(
                    || HashMap::new(),
                    |mut a, b| -> Result<_, Error> {
                        a.extend(b.into_iter());
                        Ok(a)
                    },
                )?
        } else {
            profiles
                .iter()
                .try_fold(HashMap::new(), credentials_folder)?
        };

        for (name, creds) in org_credentials {
            credentials_store
                .lock()
                .unwrap()
                .set_profile(name.clone(), creds)?;
        }

        credentials::save_credentials(&organization.okta_organization, &username, &password)?;
    }

    Arc::try_unwrap(credentials_store)
        .map_err(|_| format_err!("Failed to un-reference count the credentials store"))?
        .into_inner()
        .map_err(|_| format_err!("Failed to un-mutex the credentials store"))?
        .save()
}

fn fetch_credentials(
    client: &OktaClient,
    organization: &Organization,
    profile: &Profile,
) -> Result<Credentials, Error> {
    info!(
        "Requesting tokens for {}/{}",
        &organization.okta_organization.name, profile.name
    );

    let app_link = client
        .app_links(None)?
        .into_iter()
        .find(|app_link| {
            app_link.app_name == "amazon_aws" && app_link.label == profile.application_name
        }).ok_or(format_err!(
            "Could not find Okta application for profile {}/{}",
            organization.okta_organization.name,
            profile.name
        ))?;

    debug!("Application Link: {:?}", &app_link);

    let saml = client
        .get_saml_response(app_link.link_url.clone())
        .map_err(|e| {
            format_err!(
                "Error getting SAML response for profile {} ({})",
                profile.name,
                e
            )
        })?;

    trace!("SAML response: {:?}", saml);

    let roles = saml.roles;

    debug!("SAML Roles: {:?}", &roles);

    let role: Role = roles
        .into_iter()
        .find(|r| r.role_name().map(|r| r == profile.role).unwrap_or(false))
        .ok_or(format_err!(
            "No matching role ({}) found for profile {}",
            profile.role,
            &profile.name
        ))?;

    trace!(
        "Found role: {} for profile {}",
        role.role_arn,
        &profile.name
    );

    let assumption_response = aws::role::assume_role(role, saml.raw)
        .map_err(|e| format_err!("Error assuming role for profile {} ({})", profile.name, e))?;

    let credentials = assumption_response.credentials.ok_or(format_err!(
        "Error fetching credentials from assumed AWS role"
    ))?;

    trace!("Credentials: {:?}", credentials);

    Ok(credentials)
}
