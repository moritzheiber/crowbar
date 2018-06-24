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
extern crate regex;
extern crate reqwest;
extern crate rpassword;
extern crate rusoto_core;
extern crate rusoto_credential;
extern crate rusoto_sts;
extern crate stderrlog;
#[macro_use]
extern crate serde_derive;
extern crate serde_ini;
extern crate serde_str;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate glob;
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
use structopt::StructOpt;

use failure::Error;
use glob::Pattern;

#[derive(Clone, StructOpt, Debug)]
pub struct Opt {
    /// Profile to update
    #[structopt(default_value = "*", parse(try_from_str))]
    pub profiles: Pattern,

    /// Okta organization to use
    #[structopt(short = "o", long = "organizations", default_value = "*", parse(try_from_str))]
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
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();

    stderrlog::new()
        .module(module_path!())
        .quiet(opt.quiet)
        .verbosity(opt.verbosity + 2)
        .init()?;

    let config = Config::new()?;

    let mut credentials_store = CredentialsStore::new()?;

    let organizations = config
        .organizations()
        .filter(|o| opt.organizations.matches(&o.name))
        .collect::<Vec<Organization>>();

    if organizations.is_empty() {
        warn!("No organizations found called {}", opt.organizations);
    } else {
        for mut organization in organizations {
            info!("Evaluating profiles in {}", organization.name);

            let session_id = organization.okta_session(opt.force_new)?;

            let profiles = organization
                .profiles(&session_id)?
                .filter(|p| opt.profiles.matches(&p.id))
                .collect::<Vec<Profile>>();

            if profiles.is_empty() {
                warn!(
                    "No profiles found called {} in {}",
                    opt.profiles, organization.name
                );
            } else {
                for profile in profiles {
                    info!("Generating tokens for {}", &profile.id);

                    let mut saml = saml::Response::from_okta_session_id(
                        &organization.name,
                        profile.application.link_url.clone(),
                        &session_id,
                    )?;

                    debug!("SAML assertion: {:?}", saml);

                    match saml
                        .roles
                        .into_iter()
                        .find(|r| r.role_name().map(|r| r == profile.role).unwrap_or(false))
                    {
                        Some(role) => {
                            debug!("Role: {:?}", role);

                            let assumption_response = aws::role::assume_role(role, saml.raw)?;
                            if let Some(credentials) = assumption_response.credentials {
                                debug!("Credentials: {:?}", credentials);

                                credentials_store.set_profile(profile.id.clone(), credentials)?;
                            } else {
                                error!("Error fetching credentials from assumed AWS role")
                            }
                        }
                        None => error!(
                            "No matching role ({}) found for profile {}",
                            profile.role, &profile.id
                        ),
                    }
                }
            }
        }

        credentials_store.save()?;
    }

    Ok(())
}
