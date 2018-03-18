#![warn(unused)]

extern crate base64;
extern crate dialoguer;
#[macro_use]
extern crate failure;
extern crate keyring;
extern crate kuchiki;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate path_abs;
extern crate regex;
extern crate reqwest;
extern crate rusoto_core;
extern crate rusoto_credential;
extern crate rusoto_sts;
#[macro_use]
extern crate serde_derive;
extern crate serde_ini;
extern crate serde_json;
extern crate serde_str;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate sxd_document;
extern crate sxd_xpath;
extern crate toml;
extern crate username;

mod okta;
mod aws;
mod config;
mod credentials;
mod saml;

use config::Config;
use aws::credentials::CredentialsStore;

use failure::Error;
use path_abs::PathDir;
use structopt::StructOpt;
use loggerv::Logger;

use std::env;
use std::process;

fn main() {
    fn run() -> Result<(), Error> {
        let args_opts = Config::from_args();

        Logger::new()
            .verbosity(args_opts.verbosity)
            .level(true)
            .module_path(true)
            .init()?;

        let configs = match config_dir() {
            Ok(dir) => Config::from_dir(&dir)?,
            Err(e) => {
                warn!("{}, using default config", e);
                vec![Ok(Config::default())]
            }
        };

        let mut credentials_store = CredentialsStore::new()?;

        for config in configs {
            let opts = args_opts.clone().merge(config?);

            let org = opts.organization.clone().unwrap();

            let username = match opts.username.clone() {
                Some(username) => username,
                None => (|| credentials::get_username(&org))()?,
            };

            let password = credentials::get_password(&org, &username, opts.force_new)?;

            let login_request =
                okta::OktaLoginRequest::from_credentials(username.clone(), password.clone());
            let session_id = okta::login(&org, &login_request)?;

            let okta_apps = okta::get_apps(&org, &session_id)?;

            let profile_spec = opts.profile.clone();

            for profile in opts.profiles() {
                let profile = profile?;

                if let Some(profile_spec) = profile_spec.clone() {
                    if profile.id != profile_spec {
                        continue;
                    }
                }

                info!("Generating tokens for {}", &profile.id);

                let app = okta_apps
                    .iter()
                    .find(|app| app.app_name == "amazon_aws" && app.label == profile.application);

                match app {
                    Some(app) => {
                        let mut saml =
                            saml::Response::from_okta(&org, app.link_url.clone(), &session_id)?;
                        debug!("SAML assertion: {:?}", saml);

                        let saml_raw = saml.raw;

                        for role in saml.roles {
                            if role.role_name()? == profile.role {
                                debug!("Role: {:?}", role);

                                let assumption_response =
                                    aws::role::assume_role(role, saml_raw.clone())?;
                                if let Some(credentials) = assumption_response.credentials {
                                    debug!("Credentials: {:?}", credentials);

                                    credentials_store.set_profile(profile.id.clone(), credentials)?;
                                } else {
                                    error!("Error fetching credentials from assumed AWS role")
                                }
                            }
                        }
                    }
                    None => error!("Could not find application {}", &profile.id),
                }
            }

            credentials::set_credentials(&org, &username, &password);
        }

        credentials_store.save()
    }

    if let Err(e) = run() {
        error!("{:?}", e);
        process::exit(1);
    }
}

fn config_dir() -> Result<PathDir, Error> {
    match env::home_dir() {
        None => bail!("Could not get home dir"),
        Some(home_dir) => PathDir::create_all(home_dir.join(".oktaws")).map_err(|e| e.into()),
    }
}
